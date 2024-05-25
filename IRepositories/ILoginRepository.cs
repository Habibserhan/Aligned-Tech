using Aligned.Models;

namespace Aligned.IRepositories
{
    public interface ILoginRepository
    {
        bool AuthenticateUser(string email, string password);
        User GetUserByEmail(string email);
        User GetUserById(Guid userId);
        List<string> GetUserRoles(Guid userId);
        List<Permission> GetUserPermissions(Guid userId);
    }
}
