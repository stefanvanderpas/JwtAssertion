using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace JwtAssertionCreator
{
    public static class JwtAssertionHelper
    {
        public static string CreateJwtAssertion(string tenantId, string clientId, string commonName)
        {
            var jwtSegments = new List<string>();
            var cert = CertificateReader.ReadCertificateFromStore(commonName);

            jwtSegments.Add(CreateHeader(cert));
            jwtSegments.Add(CreatePayload(clientId, tenantId));

            var encodedHeaderAndPayload = string.Join(".", jwtSegments);

            jwtSegments.Add(CreateSign(cert, encodedHeaderAndPayload));

            return string.Join(".", jwtSegments);
        }

        private static string CreateHeader(X509Certificate2 cert)
        {
            var header = new { alg = "RS256", typ = "JWT", x5t = Base64UrlEncoder.Encode(cert.GetCertHash()) };
            return Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
        }

        private static string CreatePayload(string clientId, string tenantId)
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var issueTime = DateTime.Now;

            var exp = (int)issueTime.AddDays(2).Subtract(utc0).TotalSeconds;
            var nbf = (int)issueTime.AddDays(-2).Subtract(utc0).TotalSeconds;
            var payload = new
            {
                aud = tenantId,
                exp,
                iss = clientId,
                jti = Guid.NewGuid(),
                nbf,
                sub = clientId,
            };

            return Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        }

        private static string CreateSign(X509Certificate2 cert, string encodedHeaderAndPayload)
        {
            var rsaP = cert.GetRSAPrivateKey();
            var signed = rsaP.SignData(Encoding.UTF8.GetBytes(encodedHeaderAndPayload), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Base64UrlEncoder.Encode(signed);
        }
    }
}