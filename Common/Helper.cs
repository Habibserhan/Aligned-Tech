using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using System.Data.SqlClient;
using Aligned.Models;
using System.Data.Common;
using System.Data;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Aligned.IRepositories;
using Microsoft.Extensions.Logging;
using System.Reflection;

public static class Helper
{
  
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("8A*?dFj3Yz<zN4&2!Z7@^1qM5gR^B2Fs");
    private static readonly byte[] IV = Encoding.UTF8.GetBytes("9D7f^C3!#@6aQw2*");

    #region JsonResultResponse
    public static JsonResult UnauthorizedResponse()
    {
        return new JsonResult(new { success = false, message = "Unauthorized" });
    }
    public static JsonResult ForbiddenResponse()
    {
        return new JsonResult(new { success = false, message = "You don't have access" });
    }
    public static JsonResult CreatedResponse()
    {
        return new JsonResult(new { success = true, message = "Record created successfully" });
    }
    public static JsonResult UpdateResponse()
    {
        return new JsonResult(new { success = true, message = "Record updated successfully" });
    }
    public static JsonResult DeleteResponse()
    {
        return new JsonResult(new { success = true, message = "Record deleted successfully" });
    }
    public static JsonResult FailureResponse(string message)
    {
        return new JsonResult(new { success = false, message = message });
    }
    public static JsonResult GetByIdResponse<T>(T data)
    {
        return new JsonResult(new { success = true, data });
    }

    public static JsonResult GetAllResponse<T>(IEnumerable<T> data)
    {
        return new JsonResult(new { success = true, data });
    }
    #endregion

    #region mix
    public static bool IsPasswordComplex(string password)
    {
        // Define the password complexity rules
        var hasMinimumLength = new Regex(@".{8,}"); // At least 8 characters
        var hasUpperCaseLetter = new Regex(@"[A-Z]+"); // At least one uppercase letter
        var hasLowerCaseLetter = new Regex(@"[a-z]+"); // At least one lowercase letter
        var hasDecimalDigit = new Regex(@"[0-9]+"); // At least one digit
        var hasSpecialCharacter = new Regex(@"[!@#$%^&*(),.?\\\"":{}|<>]+");

        var isValid = hasMinimumLength.IsMatch(password) &&
                      hasUpperCaseLetter.IsMatch(password) &&
                      hasLowerCaseLetter.IsMatch(password) &&
                      hasDecimalDigit.IsMatch(password) &&
                      hasSpecialCharacter.IsMatch(password);

        return isValid;
    }

    public static string GetClientIpAddress(HttpContext context)
    {
        string ipAddress = context.Connection.RemoteIpAddress?.ToString();

        if (context.Request.Headers.ContainsKey("X-Forwarded-For"))
        {
            ipAddress = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        }
        else if (context.Request.Headers.ContainsKey("X-Real-IP"))
        {
            ipAddress = context.Request.Headers["X-Real-IP"];
        }

        if (string.IsNullOrEmpty(ipAddress) || ipAddress == "::1")
        {
            ipAddress = context.Connection.RemoteIpAddress?.MapToIPv4().ToString();
        }

        if (string.IsNullOrEmpty(ipAddress))
        {
            ipAddress = "0.0.0.0";
        }

        return ipAddress;
    }

    public static byte[] EncryptStringToBytes_Aes(string plainText)
    {
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException(nameof(plainText));

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }
    }

    public static string DecryptStringFromBytes_Aes(byte[] cipherText)
    {
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException(nameof(cipherText));

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }

    public static string EncryptStringToBase64(string plainText)
    {
        return Convert.ToBase64String(EncryptStringToBytes_Aes(plainText));
    }

    public static string DecryptStringFromBase64(string base64CipherText)
    {
        return DecryptStringFromBytes_Aes(Convert.FromBase64String(base64CipherText));
    }
    #endregion

    #region Permission
    public static bool HasPermission(SqlConnection connection, Guid userId, string pageName, string permissionType)
    {
        var permissions = GetUserPermissions(connection, userId);

        var permission = permissions.FirstOrDefault(p => p.PageName.Equals(pageName, StringComparison.OrdinalIgnoreCase));
        if (permission == null)
        {
            return false;
        }

        return permissionType switch
        {
            "CanAdd" => permission.CanAdd,
            "CanEdit" => permission.CanEdit,
            "CanDelete" => permission.CanDelete,
            "CanView" => permission.CanView,
            "CanList" => permission.CanList,
            "CanImport" => permission.CanImport,
            "CanExport" => permission.CanExport,
            _ => false,
        };
    }

    public static List<Permission> GetUserPermissions(SqlConnection connection, Guid userId)
    {
        var permissions = new List<Permission>();
        using (var command = new SqlCommand("SP_GetUserPermissions", connection))
        {
            command.CommandType = System.Data.CommandType.StoredProcedure;
            command.Parameters.AddWithValue("@UserId", userId);
            connection.Open();
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    var permission = new Permission
                    {
                        PageName = reader["PageName"].ToString(),
                        CanAdd = Convert.ToBoolean(reader["CanAdd"]),
                        CanEdit = Convert.ToBoolean(reader["CanEdit"]),
                        CanDelete = Convert.ToBoolean(reader["CanDelete"]),
                        CanView = Convert.ToBoolean(reader["CanView"]),
                        CanList = Convert.ToBoolean(reader["CanList"]),
                        CanImport = Convert.ToBoolean(reader["CanImport"]),
                        CanExport = Convert.ToBoolean(reader["CanExport"])
                    };
                    permission.HasAccess = permission.CanAdd || permission.CanEdit || permission.CanDelete || permission.CanView || permission.CanList || permission.CanImport || permission.CanExport;
                    permissions.Add(permission);
                }
            }
            connection.Close();
        }
        return permissions;
    }

    #endregion

    #region JWT Token
    public static string GenerateJwtToken(string issuer, string audience, string signingSecret, string email, long expirySeconds, Guid userId)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingSecret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub, email),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("UserId", userId.ToString())
    };

        var token = new JwtSecurityToken(
            issuer,
            audience,
            claims,
            expires: DateTime.Now.AddSeconds(expirySeconds),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    public static string GenerateRefreshToken()
    {
        try
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);

                return Convert.ToBase64String(randomNumber);
            }
        }
        catch (Exception ex)
        {

            return "";
        }
    }

    public static string GetTokenFromHeaders(HttpRequest request)
    {
        var authorizationHeader = request.Headers["Authorization"].ToString();
        return authorizationHeader.StartsWith("Bearer ") ? authorizationHeader.Substring(7) : authorizationHeader;
    }

    public static bool CheckTokenValidity(SqlConnection connection, string token, HttpContext context)
    {
        try
        {
            var userId = GetUserIdFromToken(token);
            var browser = context.Request.Headers["User-Agent"].ToString();
            var pcName = Dns.GetHostName();

            using (var command = new SqlCommand("SP_CheckTokenValidity", connection))
            {
                command.CommandType = System.Data.CommandType.StoredProcedure;
                command.Parameters.AddWithValue("@UserId", userId);
                command.Parameters.AddWithValue("@Token", token);
                command.Parameters.AddWithValue("@Browser", browser);
                command.Parameters.AddWithValue("@PcName", pcName);

                connection.Open();
                var result = (int)command.ExecuteScalar();
                connection.Close();

                return result > 0;
            }
        }
        catch (SqlException ex)
        {
            throw new Exception("Error checking token validity in the database.", ex);
        }
        finally
        {
            if (connection.State == System.Data.ConnectionState.Open)
            {
                connection.Close();
            }
        }
    }

    public static Guid GetUserIdFromToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(token))
        {
            throw new SecurityTokenMalformedException("JWT is not well formed.");
        }

        var jwtToken = handler.ReadJwtToken(token);
        var userIdClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "UserId");
        return Guid.Parse(userIdClaim?.Value);
    }

    //public static string RefreshToken(string expiredToken, string refreshToken, SqlConnection connection, HttpContext context, IUserRepository userRepository, IJwtSettingsRepository jwtSettingsRepository)
    //{
    //    var userId = GetUserIdFromToken(expiredToken);
    //    var user = userRepository.GetUserById(userId);

    //    if (user != null)
    //    {
    //        using (var command = new SqlCommand("SELECT RefreshToken FROM UserToken WHERE UserId = @UserId AND Token = @Token", connection))
    //        {
    //            command.Parameters.AddWithValue("@UserId", userId);
    //            command.Parameters.AddWithValue("@Token", expiredToken);

    //            connection.Open();
    //            var storedRefreshToken = command.ExecuteScalar()?.ToString();
    //            connection.Close();

    //            if (storedRefreshToken == refreshToken)
    //            {
    //                var jwtSettings = jwtSettingsRepository.GetJwtSettings();
    //                var newToken = GenerateJwtToken(jwtSettings.JwtIssuer, jwtSettings.JwtAudience, jwtSettings.JwtSigningSecret, user.Email, Convert.ToInt64(jwtSettings.ExpiryToken), user.Id);

    //                // Update the token and expiry in the database
    //                var newExpiry = DateTime.Now.AddSeconds(Convert.ToDouble(jwtSettings.ExpiryToken));
    //                var newRefreshToken = GenerateRefreshToken();

    //                using (var updateCommand = new SqlCommand("UPDATE UserToken SET Token = @NewToken, Expiry = @NewExpiry, RefreshToken = @NewRefreshToken WHERE UserId = @UserId AND Token = @OldToken", connection))
    //                {
    //                    updateCommand.Parameters.AddWithValue("@NewToken", newToken);
    //                    updateCommand.Parameters.AddWithValue("@NewExpiry", newExpiry);
    //                    updateCommand.Parameters.AddWithValue("@NewRefreshToken", newRefreshToken);
    //                    updateCommand.Parameters.AddWithValue("@UserId", userId);
    //                    updateCommand.Parameters.AddWithValue("@OldToken", expiredToken);

    //                    connection.Open();
    //                    updateCommand.ExecuteNonQuery();
    //                    connection.Close();
    //                }

    //                return newToken;
    //            }
    //        }
    //    }

    //    return null;
    //}




    //private static bool AuthenticateUser(string email, string password, IUserRepository userRepository)
    //{
    //    return userRepository.AuthenticateUser(email, password);
    //}

    //public static bool IsTokenExpired(string token, string signingSecret)
    //{
    //    var tokenHandler = new JwtSecurityTokenHandler();
    //    var validationParameters = new TokenValidationParameters
    //    {
    //        ValidateIssuer = false,
    //        ValidateAudience = false,
    //        ValidateLifetime = false,
    //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingSecret))
    //    };

    //    try
    //    {
    //        var principal = tokenHandler.ValidateToken(token, validationParameters, out var securityToken);
    //        if (securityToken is JwtSecurityToken jwtToken)
    //        {
    //            return jwtToken.ValidTo < DateTime.UtcNow;
    //        }
    //    }
    //    catch (Exception)
    //    {
    //        return true;
    //    }

    //    return false;
    //}

    #endregion
}
