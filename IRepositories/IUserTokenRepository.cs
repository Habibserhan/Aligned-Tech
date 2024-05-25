using Aligned.Models;
using Microsoft.AspNetCore.Mvc;
using System;

namespace Aligned.IRepositories
{
    public interface IUserTokenRepository
    {
        void InsertUserToken(UserToken token);
        void DeleteOldUserTokens(Guid userId);
    }
}
