using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;

namespace Keycloak_API
{
    public class JwtAuthorization
    {
        static HttpClient client = new HttpClient();
        private IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public JwtAuthorization(IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }
        #region GenerateToken
        //public string GenerateToken(UserModel user)
        //{
        //    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        //    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        //    var claims = new[]
        //    {
        //        new Claim("user_id", user.user_id.ToString()),
        //    };

        //    var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims, expires: DateTime.Now.AddMinutes(5), signingCredentials: credentials);
        //    return new JwtSecurityTokenHandler().WriteToken(token);
        //}

        public string GenerateToken(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.user_id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique identifier for the token
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString(), ClaimValueTypes.Integer64), // Issued at
                new Claim(JwtRegisteredClaimNames.Email, user.user_email),
                new Claim("user_name", user.user_name),
                new Claim(ClaimTypes.NameIdentifier, user.user_id.ToString())
            };

            // Assuming user roles are stored in a list within the UserModel
            //foreach (var role in user.Roles)
            //{
            //    claims.Add(new Claim(ClaimTypes.Role, role));
            //}

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(30), // Token expiration time
                NotBefore = DateTime.UtcNow, // Token not valid before this time
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = credentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        #endregion
        public JwtSecurityToken ValidateToken(IHeaderDictionary headers)
        {
            try
            {
                var token = headers["Authorization"].ToString().Replace("Bearer ", "");
                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadToken(token) as JwtSecurityToken;
                var expiry = Convert.ToInt64(jsonToken.Claims.ElementAt(0).Value);
                var current_time = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
                if (current_time < expiry)
                {
                    return jsonToken;
                }
                else
                {
                    return null;
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task<HttpResponseMessage> keycloakAuth(UserModel user)
        {
            string baseUrl = "http://localhost:8080/realms/my-realm/protocol/openid-connect/token";
            //string baseUrl = "http://localhost:8080/realms/my-realm/account/";
            var values = new Dictionary<string, string>
            {
                //{ "client_id", "admin-cli" },
                { "client_id", "myclient" },
                { "client_secret", "GdcXJUVQ4g0q8P6eanmMVWxOWZfRPaFO" },
                { "grant_type", "password" },
                { "username", user.user_name },
                { "password", user.user_password }
                //{ "email", user.user_email },
            };
            var content = new FormUrlEncodedContent(values);
            //Console.WriteLine("content: " + content);
            var response = await client.PostAsync(baseUrl, content);
            Console.WriteLine("response: " + response);
            //var responsestring = await response.Content.ReadAsStringAsync();
            //Console.WriteLine("responsestring: " + responsestring);
            //return responsestring;
            return response;
        }

        public async Task<Dictionary<string, object>> adminLogin()
        {
            string baseUrl = "http://localhost:8080/realms/master/protocol/openid-connect/token";
            var values = new Dictionary<string, string>
            {
                { "client_id", "admin-cli" },
                { "grant_type", "password" },
                { "username", "admin" },
                { "password", "admin" },
                { "client_secret", "Lrldk8dcqCPxtKng7YBxvuebQpOo5qyc" },
                { "scope", "openid" }
            };
            var content = new FormUrlEncodedContent(values);

            var response = await client.PostAsync(baseUrl, content);
            var responsestring = await response.Content.ReadAsStringAsync();

            var jsonResponse = JsonConvert.DeserializeObject<Dictionary<string, object>>(responsestring);
            return jsonResponse;
        }

        public async Task<HttpResponseMessage> createKeyCloakUser(string adminToken, UserModel userModel)
        {
            var contentType = new MediaTypeWithQualityHeaderValue("application/json");
            string baseUrl = "http://localhost:8080/admin/realms/my-realm/users";

            var user = new Dictionary<string, object>
            {
                //{ "firstName", userModel.user_name },
                { "firstName", "NA" },
                { "lastName", "NA" },
                //{ "username", userModel.user_email },
                { "username", userModel.user_name },
                { "email", userModel.user_email },
                { "enabled", true },
                { "credentials", new List<Dictionary<string, object>>
                    {
                        new Dictionary<string, object>
                        {
                            { "type", "password" },
                            { "value", userModel.user_password },
                            { "temporary", false }
                        }
                    }
                }
            };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

            var jsonData = JsonConvert.SerializeObject(user);
            var contentData = new StringContent(jsonData, Encoding.UTF8, "application/json");

            var response = await client.PostAsync(baseUrl, contentData);
            Console.WriteLine("response: " + response);
            //var responsestring = await response.Content.ReadAsStringAsync();

            //var jsonResponse = JsonConvert.DeserializeObject<Dictionary<string, object>>(responsestring);
            return response;
        }

    }
}
