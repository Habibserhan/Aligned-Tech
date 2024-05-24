using Aligned.IRepositories;
using Aligned.Models;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace Aligned.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JwtSettingsController : ControllerBase
    {
        private readonly IJwtSettingsRepository _jwtSettingsRepository;

        public JwtSettingsController(IJwtSettingsRepository jwtSettingsRepository)
        {
            _jwtSettingsRepository = jwtSettingsRepository;
        }

        [HttpGet]
        public async Task<IActionResult> GetJwtSettings()
        {
            var jwtSettings = _jwtSettingsRepository.GetJwtSettings();
            jwtSettings.JwtIssuer = Helper.DecryptStringFromBase64(jwtSettings.JwtIssuer);
            jwtSettings.JwtAudience = Helper.DecryptStringFromBase64(jwtSettings.JwtAudience);
            jwtSettings.JwtSigningSecret = Helper.DecryptStringFromBase64(jwtSettings.JwtSigningSecret);
            return Ok(jwtSettings);
        }

        [HttpPost]
        public async Task<IActionResult> CreateJwtSettings([FromBody] JwtSettings jwtSettings)
        {
            // Encrypt settings
            var encryptedJwtSettings = new JwtSettings
            {
                JwtIssuer = Helper.EncryptStringToBase64(jwtSettings.JwtIssuer),
                JwtAudience = Helper.EncryptStringToBase64(jwtSettings.JwtAudience),
                JwtSigningSecret = Helper.EncryptStringToBase64(jwtSettings.JwtSigningSecret),
                ExpiryToken = jwtSettings.ExpiryToken
            };

            _jwtSettingsRepository.UpdateJwtSettings(encryptedJwtSettings);
            return Ok();
        }
    }
}
