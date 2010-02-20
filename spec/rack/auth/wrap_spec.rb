require 'spec/specs_config'
require 'lib/rack/auth/wrap'

describe "OAuth WRAP v.0.9.7.2 Authentication Mechanism using SWT on Rack Module" do
  it "should return 401 with WWW-Authenticate: WRAP when a token is invalid" do
    env = Rack::MockRequest.env_for("/", 'Authorization' => 'WRAP access_token=invalid_token')

    (mock_app = mock).expects(:call).with(env).never
    (mock_validator = mock).expects(:valid?).with("invalid_token").returns(false)

    (mock_request = mock).stubs(:token).returns("invalid_token")
    mock_request.stubs(:provided?).returns(true)
    mock_request.stubs(:is_wrap?).returns(true)
    
    Rack::Auth::WRAP::Request.expects(:new).with(env).returns(mock_request)
    SimpleWebToken::SimpleWebTokenHandler.expects(:new).with(:shared_secret => "foo_bar").returns(mock_validator)

    response_code, headers, body = Rack::Auth::WRAP.new(mock_app, :shared_secret => "foo_bar").call(env)

    response_code.should == 401
    headers['WWW-Authenticate'].should == 'WRAP'
    headers['Content-Length'].should == '0'
  end
  
  it "should not run assertions when not provided" do
    env = Rack::MockRequest.env_for("/")
    (mock_app = mock).expects(:call).with(env).returns([200, {'Content-Length' => '0'}]).once
    
    SimpleWebToken::SimpleWebTokenHandler.expects(:new).never
    response_code, headers, body = Rack::Auth::WRAP.new(mock_app, :shared_secret => "foo_bar").call(env)

    response_code.should == 200
    headers['Content-Length'].should == '0'
  end
  
  it "should assign pased token to REMOTE_USER when valid" do
    env = Rack::MockRequest.env_for("/", 'Authorization' => 'WRAP access_token=token')
    
    (mock_app = mock).expects(:call).with(env).returns([200, {'Content-Length' => '0'}]).once
    
    (mock_handler = mock).expects(:valid?).with("token").returns(true)
    (mock_handler).expects(:parse).with("token").returns({'UserName' => "us3r", "ExpiresOn" => "1234098765"})

    (mock_request = mock).stubs(:token).returns("token")
    mock_request.stubs(:provided?).returns(true)
    mock_request.stubs(:is_wrap?).returns(true)
    
    Rack::Auth::WRAP::Request.expects(:new).with(env).returns(mock_request)
    SimpleWebToken::SimpleWebTokenHandler.expects(:new).with(:shared_secret => "foo_bar").returns(mock_handler)

    response_code, headers, body = Rack::Auth::WRAP.new(mock_app, :shared_secret => "foo_bar").call(env)

    response_code.should == 200
    headers['Content-Length'].should == '0'
    env['REMOTE_USER'].nil?.should == false
    env['REMOTE_USER']['UserName'].should == 'us3r'
    env['REMOTE_USER']['ExpiresOn'].nil?.should == false
  end
end