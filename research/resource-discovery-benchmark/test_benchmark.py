import unittest
from benchmark import parse_purl, direct_resources, provider_queries

class PurlTests(unittest.TestCase):
    def test_maven_coordinates_and_artifacts(self):
        p=parse_purl('pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.98')
        self.assertEqual((p['namespace'],p['name'],p['version']),('org.apache.tomcat','tomcat-catalina','9.0.98'))
        urls=[u for u,_ in direct_resources(p)]
        self.assertIn('https://repo1.maven.org/maven2/org/apache/tomcat/tomcat-catalina/9.0.98/tomcat-catalina-9.0.98.jar',urls)
        self.assertIn('https://repo1.maven.org/maven2/org/apache/tomcat/tomcat-catalina/9.0.98/tomcat-catalina-9.0.98-sources.jar',urls)

    def test_debian_plus_epoch_arch_distribution(self):
        p=parse_purl('pkg:deb/debian/libnettle6@1%3A3.3-1%2Bb2?arch=amd64&distro=debian-9.5')
        self.assertEqual(p['version'],'1:3.3-1+b2'); self.assertEqual(p['qualifiers'],{'arch':'amd64','distro':'debian-9.5'})
        urls=[u for u,_ in direct_resources(p)]
        self.assertEqual(len(urls),1); self.assertTrue(urls[0].endswith('/binfiles'))

    def test_deps_dev_not_called_for_debian(self):
        p=parse_purl('pkg:deb/debian/libglapi-mesa@13.0.6-1%2Bb2?arch=amd64&distro=debian-9.5')
        self.assertFalse(any(x[0]=='deps.dev' for x in provider_queries(p)))

if __name__=='__main__': unittest.main()
