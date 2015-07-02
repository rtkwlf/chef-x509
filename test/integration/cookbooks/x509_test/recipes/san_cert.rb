include_recipe 'x509'

x509_certificate 'service-www.example.com' do
  key ::File.join(node['x509']['tls_root'], 'private', 'www.example.com.key')
  certificate ::File.join(node['x509']['tls_root'], 'certs', 'www.example.com.crt')
  ca 'cshtc'
  bits 4096
  days 732
  subject_alt_name [ 'www.example.com', 'example.com', 'localhost' ]
end
