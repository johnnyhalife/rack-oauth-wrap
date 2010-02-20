require 'spec/specs_config'
require 'lib/rack/auth/wrap'

describe "Request behavior for Client calls	protected	resource using	HTTP Header" do
  it "should tell if the request is using WRAP Authentication method" do
    env = Rack::MockRequest.env_for("/", 'HTTP_AUTHORIZATION' => 'WRAP access_token=invalid_token')
    request = Rack::Auth::WRAP::Request.new(env)
    request.is_wrap?.should == true
  end
  
  it "should tell if the request isn't using WRAP Authentication method" do
    env = Rack::MockRequest.env_for("/", 'HTTP_AUTHORIZATION' => 'MD5 an_invalid_hash')
    request = Rack::Auth::WRAP::Request.new(env)
    request.is_wrap?.should == false
  end
  
  it "should tell whether the request is given or not" do
    wrap_env = Rack::MockRequest.env_for("/", 'HTTP_AUTHORIZATION' => 'WRAP with_token')
    wrap_request = Rack::Auth::WRAP::Request.new(wrap_env)
    wrap_request.provided?.should == true
    
    non_wrap_env = Rack::MockRequest.env_for("/")
    non_wrap_request = Rack::Auth::WRAP::Request.new(non_wrap_env)
    non_wrap_request.provided?.should == false
  end
  
  it "should return the token unescaped from the request" do
    simple_web_token = {'Issuer' => 'http://myidentityprovider2/', 
                        'Audience' => 'http://site/',
                        'ExpiresOn' => (Time.now.to_i + 60).to_s}.map{|k, v| "#{k}=#{CGI.escape(v)}"}.join("&")

    env = Rack::MockRequest.env_for("/", 'HTTP_AUTHORIZATION' => "WRAP access_token=#{CGI.escape(simple_web_token)}")
    request = Rack::Auth::WRAP::Request.new(env)
    request.token.should == simple_web_token
  end
end

