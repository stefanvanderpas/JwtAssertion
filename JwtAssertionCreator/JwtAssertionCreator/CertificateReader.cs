using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace JwtAssertionCreator
{
    public static class CertificateReader
    {
        public static X509Certificate2 ReadCertificateFromStore(string commonName)
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            var certCollection = store.Certificates;
            var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
            var signingCert = currentCerts.Find(X509FindType.FindBySubjectName, commonName, false);
            var cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();

            store.Close();
            return cert;
        }
    }
}
