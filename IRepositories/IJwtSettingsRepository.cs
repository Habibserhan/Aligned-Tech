using Aligned.Models;

namespace Aligned.IRepositories
{
    public interface IJwtSettingsRepository
    {
        JwtSettings GetJwtSettings();
        void UpdateJwtSettings(JwtSettings jwtSettings);
    }
}
