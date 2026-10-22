using System;
using System.Data.SqlClient;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace DexSecFixture
{
    [ApiController]
    [Route("api/products")]
    public class ProductsController : ControllerBase
    {
        [HttpGet("search")]
        public IActionResult Search()
        {
            var term = Request.Query["q"];
            using var command = new SqlCommand("SELECT id, name FROM Products WHERE name = '" + term + "'", Connection);
            return Content(command.ExecuteScalar()?.ToString());
        }

        [HttpGet("download")]
        public IActionResult Download()
        {
            var name = Request.Query["file"];
            var path = System.IO.Path.Combine("C:\\data", name);
            return Content(System.IO.File.ReadAllText(path));
        }

        [HttpPost("import")]
        public IActionResult Import()
        {
            var host = Request.Query["host"];
            Process.Start("ping", "-n", "1", host);
            return Ok();
        }
    }
}
