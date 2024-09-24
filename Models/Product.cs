namespace project.Models
{
    public class Product
    {
        public int ProductId { get; set; } 
        public string? ProductName { get; set; }
        public int Quantity { get; set; }
        public string? Barcode { get; set; }
        public int UserId { get; set; }
        public string? Role { get; set; }
    }
}
