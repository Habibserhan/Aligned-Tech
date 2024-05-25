using Aligned.Models;
using System.Collections.Generic;

namespace Aligned.IRepositories
{
    public interface IUserRepository
    {
        void CreateUser(User user);
        bool AuthenticateUser(string email, string password);
        User GetUserByEmail(string email);
        void UpdateUser(User user);
        User GetUserById(Guid userId);
        List<string> GetUserRoles(Guid userId);
        List<Permission> GetUserPermissions(Guid userId);
    }
}
