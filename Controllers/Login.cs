using Aligned.IRepositories;
using Aligned.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Aligned.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{v:apiVersion}/[controller]")]
    public class LoginController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        private readonly IJwtSettingsRepository _jwtSettingsRepository;
        private readonly IUserTokenRepository _userTokenRepository;
        private readonly SqlConnection _connection;

        public LoginController(IUserRepository userRepository, IJwtSettingsRepository jwtSettingsRepository, IUserTokenRepository userTokenRepository, IConfiguration configuration)
        {
            _userRepository = userRepository;
            _jwtSettingsRepository = jwtSettingsRepository;
            _userTokenRepository = userTokenRepository;
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
        }

        [HttpPost("login")]
        public async Task<JsonResult> Loginuser([FromBody] LoginModel loginModel)
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
