using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Oracle.ManagedDataAccess.Client;
using project.packages;
using project.Model;
using System.Data;
using project.Models;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

namespace project.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        IPKG_TO_DO package;
        private readonly IPKG_TO_DO _package;
        private IConfiguration _configuration;

        public HomeController(IPKG_TO_DO package, IConfiguration configuration)
        {
            _package = package;
            _configuration = configuration;
        }


        [HttpPost("CreateUser")]
        public async Task<IActionResult> CreateUser(UserData userData)
        {
            try
            {

                await _package.CreateUser(userData.Email, userData.EmployeeLastName, userData.EmployeeName, userData.OrganizationAddress, userData.OrganizationName, userData.Password,userData.personId, userData.PhoneNumber, userData.Role );
                Console.WriteLine(userData);


                return Ok(new { message = "User created successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"An error occurred: {ex.Message}" });
            }
        }

        [HttpPost("UpdateUserByPersonId")]
        public async Task<IActionResult> UpdateUserByPersonId([FromBody] Update request)
        {
            try
            {
                await _package.UpdateUserByPersonId(
            request.PersonId,
            request.EmployeeName,
            request.EmployeeSurname,
            request.Password,
            request.Role,
            request.Telephone,
            request.OrgName
                );
                return Ok(new { message = "User updated successfully" });
            }
            catch (OracleException ex)
            {
                return BadRequest(new { message = $"Oracle error occurred: {ex.Message}" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"An error occurred: {ex.Message}" });
            }
        }


        [HttpPost("DeleteUser")]
        public async Task<IActionResult> DeleteUser([FromBody] int userId)
        {
            var message = await _package.DeleteUser(userId);
            return Ok(new { message });
        }


        [HttpPost("AddProduct")]
        public async Task<IActionResult> AddProduct([FromBody] Product productDto)
        {
            if (productDto == null)
            {
                return BadRequest(new { message = "Invalid product data." });
            }

            try
            {
                await _package.AddProductToWarehouse(
                    productDto.ProductName,
                    productDto.Quantity,
                    productDto.UserId
                );

                return Ok(new { message = "Product added successfully." });
            }
            catch (Exception ex)
            {
                // Log the exception
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = $"An error occurred: {ex.Message}" });
            }
        }


        [HttpPost("EditProduct")]
        public async Task<IActionResult> EditProduct([FromBody] Product productDto)
        {
            if (productDto == null)
            {
                return BadRequest(new { message = "Invalid product data." });
            }

            try
            {
                await _package.EditProductInWarehouse(
                    productDto.ProductId,
                    productDto.ProductName,
                    productDto.Quantity,
                    productDto.Barcode,
                    productDto.UserId
                );

                return Ok(new { message = "Product updated successfully." });
            }
            catch (Exception ex)
            {
                // Log the exception
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = $"An error occurred: {ex.Message}" });
            }
        }

        [Authorize(Roles = "manager")]
        [HttpGet("FetchProducts")]
        public async Task<IActionResult> FetchProducts()
        {
            try
            {
                var products = await _package.FetchProducts();

                if (products == null || !products.Any())
                {
                    return NotFound(new { message = "No products found." });
                }

                return Ok(products);
            }
            catch (Exception ex)
            {
               
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = $"An error occurred: {ex.Message}" });
            }
        }
        [HttpGet("FetchTakenProducts")]
        public async Task<IActionResult> FetchTakenProducts()
        {
            try
            {
                var products = await _package.FetchTakenProducts();

                if (products == null || !products.Any())
                {
                    return NotFound(new { message = "No products found." });
                }

                return Ok(products);
            }
            catch (Exception ex)
            {
               
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = $"An error occurred: {ex.Message}" });
            }
        }

        [Authorize(Roles = "operator")]
        [HttpGet("FetchProductbyuserId/{userId}")]
        public async Task<IActionResult> FetchProductbyuserId(int userId)
        {
            try
            {
               
                var products = await _package.FetchProductbyuserId(userId);

                if (products == null || !products.Any())
                {
                    return NotFound(new { message = "No products found for the specified user." });
                }

                return Ok(products);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = $"An error occurred: {ex.Message}" });
            }
        }


        [Authorize(Roles = "manager")]
        [HttpPost]
        [Route("RemoveProduct")]
        public async Task<IActionResult> RemoveProductAsync([FromBody] Product product)
        {
            if (product == null)
            {
                return BadRequest("Product data is required.");
            }

            try
            {
                await _package.RemoveProductAsync(product.UserId, product.Barcode, product.Quantity);
                return Ok("Product removed successfully.");
            }
            catch (Exception ex)
            {
              
                return BadRequest($"Error: {ex.Message}");
            }
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(UserDto request)
        {
            if (request == null)
            {
                return BadRequest(new { message = "Invalid request." });
            }

            try
            {
                var loginResponse = await _package.LoginUser(request.UserName, request.Password);

                if (loginResponse != null)
                {
                    return Ok(new
                    {
                        token = loginResponse.Token,
                        role = loginResponse.Role,
                        userId = loginResponse.UserId
                    });
                }
                else
                {
                    return Unauthorized(new { message = "Invalid username or password." });
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = $"An error occurred: {ex.Message}" });
            }
        }


        public static UserData user = new UserData();


        [Authorize(Roles = "admin")]
        [HttpGet("GetAllProjectUsersAsync")]
        public async Task<IActionResult> GetAllProjectUsersAsync()
        {


            var users = await _package.GetAllProjectUsersAsync();


            return Ok(users);
        }



        [HttpPost("UpdateUserStatus")]
        public async Task<IActionResult> UpdateUserStatus([FromBody] UpdateUserStatusRequest request)
        {
            try
            {
                await _package.UpdateUserStatus(request.UserId, request.Status);
                return Ok(new { message = "User status updated successfully." });
            }
            catch (Exception ex)
            {
 
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = $"An error occurred: {ex.Message}" });
            }
        }


        [Authorize(Roles = "admin")]
        [HttpGet("GetAllOrganizationNamesAsync")]
        public async Task<IActionResult> GetAllOrganizationNamesAsync()
        {
            try
            {
                var orgNames = await _package.GetAllOrganizationNamesAsync();
                return Ok(orgNames);
            }
            catch (Exception ex)
            {


                return StatusCode(500, "An error occurred while processing your request.");
            }
        }

























        /*  [HttpPost("jwtregister")]
          public ActionResult<UserData> RegisterJWT(UserDto request)
          {
              string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

              user.Username = request.UserName;
              user.PasswordHash = passwordHash;
              return Ok(user);
          }

          [HttpPost("jwtlogin")]
          public ActionResult<UserData> LoginJWT(UserDto request)
          {
              if(user.Username!=request.UserName)
              {
                  return BadRequest("user ver vipove");
              }
              if(!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
              {
                  return BadRequest("araswori paroli");
              }
              string token = CreateToken(user);
              return Ok(token);
          }*/

        /*private string CreateToken(UserData user)
        {
            List<Claim> claims = new List<Claim>
            {
               new Claim(ClaimTypes.Name, user.Username),
               new Claim(ClaimTypes.Role, "admin")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires : DateTime.Now.AddDays(1),
                signingCredentials :cred
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }*/

    }

}
