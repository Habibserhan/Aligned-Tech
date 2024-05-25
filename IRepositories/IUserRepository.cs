using Aligned.Models;
using System.Collections.Generic;

namespace Aligned.IRepositories
{
    public interface IUserRepository
    {
        void CreateUser(User user);
  
        void UpdateUser(User user);
   
    }
}
