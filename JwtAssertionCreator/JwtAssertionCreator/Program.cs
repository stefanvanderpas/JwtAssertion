using System;

namespace JwtAssertionCreator
{
    class Program
    {
        private readonly static string clientId = "testClient";
        private readonly static string tenantId = "testTenant";
        private readonly static string _commonName = "localhost";

        static void Main(string[] args)
        {
            Console.WriteLine("Type start to create JWT Assertion");
            var start = Console.ReadLine();
            if(start.Equals("start"))
            {
                Console.WriteLine("Start Creating JWT Assertion");
                var jwtAssertionHelper = JwtAssertionHelper.CreateJwtAssertion(tenantId, clientId, _commonName);
                Console.WriteLine($"Jwt Assertion: {jwtAssertionHelper}");
            }
        }
    }
}
