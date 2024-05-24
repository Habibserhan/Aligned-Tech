using Aligned.IRepositories;
using Aligned.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

[ApiController]
[ApiVersion("1.0")]
[Route("api/v{v:apiVersion}/[controller]")]
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

    [HttpPost("update")]
   
    public async Task<IActionResult> Update([FromBody] User user)
    {
        string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
        if (!Helper.CheckTokenValidity(_connection, token, HttpContext))
        {
            return Unauthorized();
        }

        var userId = Helper.GetUserIdFromToken(token);

        if (!Helper.HasPermission(_connection, userId, "users", "CanEdit"))
        {
            return Forbid();
        }

        try
        {
            _userRepository.UpdateUser(user);
            return new JsonResult(new { success = true, message = "User updated successfully" });
        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }

    [HttpPost("create")]
   
    public async Task<IActionResult> Create([FromBody] User user)
    {
        string token = HttpContext.Request.Headers["Authorization"].ToString().Split(' ')[1];
        if (!Helper.CheckTokenValidity(_connection, token, HttpContext))
        {
            return Unauthorized();
        }

        var userId = Helper.GetUserIdFromToken(token);

        if (!Helper.HasPermission(_connection, userId, "users", "CanAdd"))
        {
            return Forbid();
        }

        try
        {
            _userRepository.CreateUser(user);
            return new JsonResult(new { success = true, message = "User created successfully" });
        }
        catch (Exception ex)
        {
            return new JsonResult(new { success = false, message = ex.Message });
        }
    }
}
