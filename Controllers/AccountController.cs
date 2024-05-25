using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Data.SqlClient;
using Aligned.IRepositories;
using Aligned.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using System.Net;

namespace Aligned.Controllers
{
    [ApiController]
    [Route("api/v1/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        private readonly IJwtSettingsRepository _jwtSettingsRepository;
        private readonly IUserTokenRepository _userTokenRepository;
        private readonly SqlConnection _connection;

        public AccountController(
            IUserRepository userRepository,
            IJwtSettingsRepository jwtSettingsRepository,
            IUserTokenRepository userTokenRepository,
            IConfiguration configuration)
        {
            _userRepository = userRepository;
            _jwtSettingsRepository = jwtSettingsRepository;
            _userTokenRepository = userTokenRepository;
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
        }

        private IActionResult ValidateTokenAndPermission(string permissionType)
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
            var jwtSettings = _jwtSettingsRepository.GetJwtSettings();

            if (Helper.IsTokenExpired(token, jwtSettings.JwtSigningSecret))
            {
                var newToken = Helper.RefreshToken(token, _connection, HttpContext, _userRepository, _jwtSettingsRepository);
                if (newToken != null)
                {
                    HttpContext.Response.Headers["Authorization"] = $"Bearer {newToken}";
                }
                else
                {
                    return Helper.UnauthorizedResponse();
                }
            }
            else if (!Helper.CheckTokenValidity(_connection, token, HttpContext))
            {
                return Helper.UnauthorizedResponse();
            }

            var userId = Helper.GetUserIdFromToken(token);
            if (!Helper.HasPermission(_connection, userId, "users", permissionType))
            {
                return Helper.ForbiddenResponse();
            }

            return null;
        }



        [HttpPost("update")]
        public IActionResult UpdateUser([FromBody] User user)
        {
            var result = ValidateTokenAndPermission("CanEdit");
            if (result != null)
            {
                return result;
            }

            try
            {
                _userRepository.UpdateUser(user);
                return Helper.UpdateResponse();
            }
            catch (Exception ex)
            {
                return Helper.FailureResponse(ex.Message);
            }
        }

        [HttpPost("create")]
        public IActionResult CreateUser([FromBody] User user)
        {
            var result = ValidateTokenAndPermission("CanAdd");
            if (result != null)
            {
                return result;
            }

            try
            {
                _userRepository.CreateUser(user);
                return Helper.CreatedResponse();
            }
            catch (Exception ex)
            {
                return Helper.FailureResponse(ex.Message);
            }
        }

        //[HttpPost("delete")]
        //public IActionResult DeleteUser([FromBody] Guid userId)
        //{
        //    var result = ValidateTokenAndPermission("CanDelete");
        //    if (result != null)
        //    {
        //        return result;
        //    }

        //    try
        //    {
        //        _userRepository.DeleteUser(userId);
        //        return Helper.DeleteResponse();
        //    }
        //    catch (Exception ex)
        //    {
        //        return Helper.FailureResponse(ex.Message);
        //    }
        //}

        [HttpPost("login")]
        public IActionResult LoginUser([FromBody] LoginModel loginModel)
        {
            if (_userRepository.AuthenticateUser(loginModel.Email, loginModel.Password))
            {
                var user = _userRepository.GetUserByEmail(loginModel.Email);
                var roles = _userRepository.GetUserRoles(user.Id);
                var jwtSettings = _jwtSettingsRepository.GetJwtSettings();
                string token = Helper.GenerateJwtToken(jwtSettings.JwtIssuer, jwtSettings.JwtAudience, jwtSettings.JwtSigningSecret, loginModel.Email, Convert.ToInt64(jwtSettings.ExpiryToken), user.Id);

                string ipAddress = Helper.GetClientIpAddress(HttpContext);
                string browser = Request.Headers["User-Agent"].ToString();
                string pcName = Dns.GetHostName();

                _userTokenRepository.DeleteOldUserTokens(user.Id);

                var userToken = new UserToken
                {
                    TokenId = Guid.NewGuid(),
                    UserId = user.Id,
                    Email = loginModel.Email,
                    Token = token,
                    CreatedAt = DateTime.UtcNow,
                    IpAddress = ipAddress,
                    Browser = browser,
                    PcName = pcName
                };
                _userTokenRepository.InsertUserToken(userToken);

                var permissions = Helper.GetUserPermissions(_connection, user.Id);

                return new JsonResult(new { statuscode = 200, success = true, roles, userToken, permissions });
            }
            return new JsonResult(new { statuscode = 400, success = false, message = "Invalid email or password" });
        }
    }
}
