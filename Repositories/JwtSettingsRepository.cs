using Aligned.Models;
using System;
using System.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Aligned.IRepositories;

namespace Aligned.Repositories
{
    public class JwtSettingsRepository : IJwtSettingsRepository
    {
        private readonly SqlConnection _connection;

        public JwtSettingsRepository(IConfiguration configuration)
        {
            _connection = new SqlConnection(configuration.GetConnectionString("DefaultConnection"));
        }

        public JwtSettings GetJwtSettings()
        {
            JwtSettings jwtSettings = null;

            try
            {
                using (SqlCommand command = new SqlCommand("SP_GetJwtSettings", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    _connection.Open();
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            jwtSettings = new JwtSettings
                            {
                                JwtIssuer = Helper.DecryptStringFromBytes_Aes((byte[])reader["EncryptedJwtIssuer"]),
                                JwtAudience = Helper.DecryptStringFromBytes_Aes((byte[])reader["EncryptedJwtAudience"]),
                                JwtSigningSecret = Helper.DecryptStringFromBytes_Aes((byte[])reader["EncryptedJwtSigningSecret"]),
                                ExpiryToken = Convert.ToInt32(reader["ExpiryToken"])
                            };
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                throw new Exception("Error retrieving JWT settings from the database.", ex);
            }
            finally
            {
                if (_connection.State == System.Data.ConnectionState.Open)
                {
                    _connection.Close();
                }
            }

            return jwtSettings;
        }

        public void UpdateJwtSettings(JwtSettings jwtSettings)
        {
            try
            {
                using (SqlCommand command = new SqlCommand("SP_UpdateJwtSettings", _connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.AddWithValue("@EncryptedJwtIssuer", Helper.EncryptStringToBytes_Aes(jwtSettings.JwtIssuer));
                    command.Parameters.AddWithValue("@EncryptedJwtAudience", Helper.EncryptStringToBytes_Aes(jwtSettings.JwtAudience));
                    command.Parameters.AddWithValue("@EncryptedJwtSigningSecret", Helper.EncryptStringToBytes_Aes(jwtSettings.JwtSigningSecret));
                    command.Parameters.AddWithValue("@ExpiryToken", jwtSettings.ExpiryToken);

                    _connection.Open();
                    command.ExecuteNonQuery();
                }
            }
            catch (SqlException ex)
            {
                throw new Exception("Error updating JWT settings in the database.", ex);
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
