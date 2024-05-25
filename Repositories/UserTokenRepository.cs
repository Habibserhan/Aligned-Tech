using Aligned.Models;
using System;
using System.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Aligned.IRepositories;

namespace Aligned.Repositories
{
    public class UserTokenRepository : IUserTokenRepository
    {
        private readonly SqlConnection _connection;

        public UserTokenRepository(IConfiguration configuration)
        {
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
        }

        public void InsertUserToken(UserToken token)
        {
            try
            {
                using (SqlCommand command = new SqlCommand("SP_InsertUserToken", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.AddWithValue("@Id", token.TokenId);
                    command.Parameters.AddWithValue("@UserId", token.UserId);
                    command.Parameters.AddWithValue("@Token", token.Token);
                    command.Parameters.AddWithValue("@CreatedAt", token.CreatedAt);
                    command.Parameters.AddWithValue("@IpAddress", token.IpAddress);
                    command.Parameters.AddWithValue("@Browser", token.Browser);
                    command.Parameters.AddWithValue("@PcName", token.PcName);
                    command.Parameters.AddWithValue("@RefreshToken", token.Refreshtoken);
                    command.Parameters.AddWithValue("@Expiry", token.Expiry);

                    _connection.Open();
                    command.ExecuteNonQuery();
                }
            }
            catch (SqlException ex)
            {
                throw new Exception("Error inserting user token into the database.", ex);
            }
            finally
            {
                if (_connection.State == System.Data.ConnectionState.Open)
                {
                    _connection.Close();
                }
            }
        }

        public void DeleteOldUserTokens(Guid userId)
        {
            try
            {
                using (SqlCommand command = new SqlCommand("SP_DeleteOldUserTokens", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@UserId", userId);

                    _connection.Open();
                    command.ExecuteNonQuery();
                }
            }
            catch (SqlException ex)
            {
                throw new Exception("Error deleting old user tokens from the database.", ex);
            }
            finally
            {
                if (_connection.State == System.Data.ConnectionState.Open)
                {
                    _connection.Close();
                }
            }
        }
    }
}
