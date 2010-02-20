require 'spec/specs_config'
require 'lib/simplewebtoken'

describe "simple web token hanlder behavior" do 
  before do
    @shared_secret = "N4QeKa3c062VBjnVK6fb+rnwURkcwGXh7EoNK34n0uM="
  end
  
  it "should validate hmac256 signature of the token" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider/', 
                        'Audience' => 'http://myapp'}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")
                        
    signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
    simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"
    
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret)
    handler.valid_signature?(simple_web_token).should == true
  end
  
  it "should validate the issuer when a single one given" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider/', 
                        'Audience' => 'http://myapp'}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")
    
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret, :trusted_issuers => 'http://myidentityprovider/')
    handler.valid_issuer?(simple_web_token).should == true
  end
  
  it "should validate the issuer when a multiple issuers are trusted" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://myapp'}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")
    
    trusted_issuers = ["http://myidentityprovider/", "http://myidentityprovider2/"]
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret, :trusted_issuers => trusted_issuers)
    handler.valid_issuer?(simple_web_token).should == true
  end
  
  it "should validate the audience when a single audience is provided" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://myapp'}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")
    
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret, :audiences => 'http://myapp')
    handler.valid_audience?(simple_web_token).should == true
  end
  
  it "should validate the audience when a multiple audiences are provided" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/'}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")

    audiences = ["http://site/", "http://mysitealias/"]    
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret, :audiences => audiences)
    handler.valid_audience?(simple_web_token).should == true
  end
  
  it "should validate if it's expired" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")    

    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret)
    handler.expired?(simple_web_token).should == false
  end
  
  it "should tell that the token is expired" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'ExpiresOn' => (Time.now.to_i - 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")

    signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
    simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"
    
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret)
    handler.expired?(simple_web_token).should == true
  end
  
  it "should throw an exception when no shared secret is provided" do
    lambda {SimpleWebToken::SimpleWebTokenHandler.new}.should raise_error SimpleWebToken::InvalidOption
  end
  
  it "should tell that a token is valid when all their components are valid" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/',
                        'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")

    signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
    simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"
 
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret)
    handler.valid?(simple_web_token).should == true
  end
  
  it "should tell that a token is invalid when no HMAC signature is provided" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/',
                        'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")
                        
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret)
    handler.valid?(simple_web_token).should == false
  end
  
  it "should tell that a token is invalid when the token is expired" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/',
                        'ExpiresOn' => (Time.now.to_i - 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")

    signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
    simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"
 
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret)
    handler.valid?(simple_web_token).should == false
  end
  
  it "should tell that a token is invalid when audience isn't trusted" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/',
                        'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")

    signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
    simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"
 
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret, 
                                                        :audiences => "http://untrusted_audience/")
    handler.valid?(simple_web_token).should == false
  end
  
  it "should tell that a token is invalid when audience isn't trusted" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/',
                        'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")

    signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
    simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"
 
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret, 
                                                        :trusted_issuers => "http://untrusted_issuer")
    handler.valid?(simple_web_token).should == false
  end
  
  it "should raise invalid token exception while trying to parse a token that isnt valid" do
     simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                          'Audience' => 'http://site/',
                          'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")

      signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
      simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"

      handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret, 
                                                          :trusted_issuers => "http://untrusted_issuer")

      lambda{ handler.parse(simple_web_token) }.should raise_error SimpleWebToken::InvalidToken
  end
  
  
  it "should return a dictionary when parsing a valid token" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/',
                        'org.security.email' => "myemail@mydomain.com",
                        'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{CGI.escape(k)}=#{CGI.escape(v)}"}.join("&")
    
    signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
    simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"
                        
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret)
    token = handler.parse(simple_web_token)

    token.nil?.should == false 
    token['Audience'].should == "http://site/"
    token['org.security.email'].should == "myemail@mydomain.com"
  end
  
  it "should return a values as tokens when sent as csv" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/',
                        'org.security.email' => "myemail@mydomain.com",
                        'Roles' => 'roleA, roleB, role1, role2',
                        'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{CGI.escape(k)}=#{CGI.escape(v)}"}.join("&")
    
    signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@shared_secret)).update(simple_web_token.toutf8).digest).strip
    simple_web_token += "&HMACSHA256=#{CGI.escape(signature)}"
                        
    handler = SimpleWebToken::SimpleWebTokenHandler.new(:shared_secret => @shared_secret)
    token = handler.parse(simple_web_token)

    token.nil?.should == false 
    token['Roles'].should == ["roleA", "roleB", "role1", "role2"]
  end
end