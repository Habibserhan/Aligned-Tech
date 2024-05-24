using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Data;
using System.Data.SqlClient;

namespace Aligned.Common
{
    public class Initiate : ControllerBase
    {
        protected int _expiryToken;
        protected string _jwtSigningSecret = string.Empty;
        protected string _jwtAudience = string.Empty;
        protected string _jwtIssuer = string.Empty;
        protected SqlConnection _connection;

        public Initiate()
        {
            IConfiguration appsettings = new ConfigurationBuilder()
                .AddJsonFile("appsettings.Development.json")
                .Build();

            _connection = new SqlConnection(appsettings.GetConnectionString("DefaultConnection"));
            LoadJwtSettings();
        }

        private void LoadJwtSettings()
        {
            try
            {
                _connection.Open();

                using (SqlCommand command = new SqlCommand("SP_GetJwtSettings", _connection))
                {
                    command.CommandType = CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            _jwtIssuer = Helper.DecryptStringFromBytes_Aes((byte[])reader["EncryptedJwtIssuer"]);
                            _jwtAudience = Helper.DecryptStringFromBytes_Aes((byte[])reader["EncryptedJwtAudience"]);
                            _jwtSigningSecret = Helper.DecryptStringFromBytes_Aes((byte[])reader["EncryptedJwtSigningSecret"]);
                            _expiryToken = reader["ExpiryToken"] != DBNull.Value ? Convert.ToInt32(reader["ExpiryToken"]) : 0;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading JWT settings: {ex.Message}");
            }
            finally
            {
                _connection.Close();
            }
        }
    }
}
