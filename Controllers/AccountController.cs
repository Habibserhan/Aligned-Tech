using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Data.SqlClient;
using Aligned.IRepositories;
using Aligned.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Diagnostics.Metrics;

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

        public AccountController(IUserRepository userRepository, IJwtSettingsRepository jwtSettingsRepository, IUserTokenRepository userTokenRepository, IConfiguration configuration)




        {
            _userRepository = userRepository;
            _jwtSettingsRepository = jwtSettingsRepository;
            _userTokenRepository = userTokenRepository;
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
        }

        private IActionResult ValidateTokenAndPermission(string permissionType)
        {
            string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];

             Guid userid =Helper.GetUserIdFromToken(token);

            if (!Helper.CheckTokenValidity(_connection, token, HttpContext))
            {
                return Helper.UnauthorizedResponse();
            }
           
                if (!Helper.HasPermission(_connection, userid, "Users", permissionType))
                {
                    return Helper.ForbiddenResponse();
                }
            

            return null;
        }


        [HttpPost("create")]
        public IActionResult CreateUser([FromBody] User user)
        {
            var result = ValidateTokenAndPermission("CanAdd");
            if (result != null)
            {
                return result;
            }

            if (!Helper.IsPasswordComplex(user.Password))
            {
                return Helper.FailureResponse("Password does not meet complexity requirements.");
            }

            try
            {
                _userRepository.CreateUser(user);
                return Helper.CreatedResponse();
            }
            catch (ArgumentException ex) when (ex.Message.Contains("Password does not meet complexity requirements"))
            {
                return Helper.FailureResponse(ex.Message);
            }
            catch (Exception ex)
            {
                return Helper.FailureResponse("An error occurred while creating the user.");
            }
        }
        [HttpPost("update")]
        public IActionResult UpdateUser([FromBody] User user)
        {
            var result = ValidateTokenAndPermission("CanEdit");
            if (result != null)
            {
                return result;
            }
            if (!Helper.IsPasswordComplex(user.Password))
            {
                return Helper.FailureResponse("Password does not meet complexity requirements.");
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


      
  
    }
}
