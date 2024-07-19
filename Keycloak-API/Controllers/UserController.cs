using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Npgsql;

namespace Keycloak_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly string connectionString;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly JwtAuthorization _jwt;

        public UserController(IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            _jwt = new JwtAuthorization(configuration, _httpContextAccessor);
            connectionString = configuration["ConnectionStrings:PostgresDb"] ?? "";
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("register")]
        public async Task<ActionResult> Register([FromBody] UserModel userModel)
        {
            // Register user in Keycloak
            var adminToken = await _jwt.adminLogin();
            string token = Convert.ToString(adminToken["access_token"]);
            var createUserKeyCloak = await _jwt.createKeyCloakUser(token, userModel);
            /* if (createUserKeyCloak == null)
             {
                 return BadRequest(new { message = "Error creating user in Keycloak." });
             }*/

            // Register user in PostgreSQL
            int userId = 0;
            try
            {
                using (NpgsqlConnection connection = new NpgsqlConnection(connectionString))
                {
                    connection.Open();
                    string registerSQL = "SELECT public.fn_create_user(@user_name, @user_email, @user_password)";
                    using (var command = new NpgsqlCommand(registerSQL, connection))
                    {
                        command.Parameters.AddWithValue("@user_name", userModel.user_name);
                        command.Parameters.AddWithValue("@user_email", userModel.user_email);
                        command.Parameters.AddWithValue("@user_password", userModel.user_password);
                        userId = Convert.ToInt32(command.ExecuteScalar());
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = "Error creating user in PostgreSQL.", error = ex.Message });
            }

            if (userId > 0)
            {
                return Ok(new { message = "User registered successfully." });
            }
            else
            {
                return BadRequest(new { message = "Error registering user." });
            }
        }
        [AllowAnonymous]
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult> Login([FromBody] UserModel userModel)
        {
            UserModel user = new UserModel();
            try
            {
                using (NpgsqlConnection connection = new NpgsqlConnection(connectionString))
                {
                    connection.Open();
                    string loginQuery = "SELECT * FROM public.fn_login(@user_identifier, @user_password)";
                    using (var command = new NpgsqlCommand(loginQuery, connection))
                    {
                        command.Parameters.AddWithValue("@user_identifier", userModel.user_email ?? userModel.user_name);
                        command.Parameters.AddWithValue("@user_password", userModel.user_password);

                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                user.user_id = reader.GetInt32(0); // Assuming the function returns the user_id as the first field
                                user.user_name = reader.GetString(1);
                                user.user_email = reader.GetString(2);
                                user.user_password = reader.GetString(3);
                            }
                            else
                            {
                                return Unauthorized(new { message = "Invalid username/email or password." });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = "Error logging in user.", error = ex.Message });
            }

            // Authenticate user with Keycloak
            var keycloakResponse = await _jwt.keycloakAuth(userModel);
            if (keycloakResponse.Contains("access_token"))
            {
                var token = _jwt.GenerateToken(user);
                return Ok(new { token });
            }
            else
            {
                return Unauthorized(new { message = "Invalid credentials." });
            }
        }

    }
}
