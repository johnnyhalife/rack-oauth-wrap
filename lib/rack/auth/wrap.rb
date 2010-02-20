require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'simplewebtoken'

module Rack
  module Auth
    # Rack::Auth::WRAP implements oAuth WRAP Authentication, as per draft-hardt-oauth-01.
    # This is a preliminary version based on the Jan 15, 2010 Web Resource Access Profiles as 
    # developed by the IETF.
    #
    # Initialize with the Rack application that you want protecting,
    # and a set of parameters that enables specific checks. The only mandatory parameter
    # is **:shared_secret** which is required for HMAC-SHA256 processing.
    #
    # See also: SimpleWebToken::SimpleWebTokenHandler
    class WRAP < AbstractHandler
      # Middleware Gem Versioning
      VERSION = "0.5.2"
      
      # Creates a new instance of Rack::Auth::WRAP, the opts can be used
      # as the following.
      # 
      #   use Rack::Auth::WRAP, :shared_secret => *secret*, 
      #                         :trusted_issuers => "http://sts.mycomp.com", 
      #                         :audiences => "http://app.domain.com"
      #
      # The parameters on the sample above are the only one that are currently supported 
      # by the SimpleWebToken handler. For more information see SimpleWebToken::SimpleWebTokenHandler
      def initialize(app, opts = {})
        @app = app
        @opts = opts
      end
      
      # Authenticates the request when it has the HTTP_AUTHORIZATION header,
      # and if the header has WRAP as the authentication format. 
      #
      # NOTE: it is sent by the client as Authorization, but Rack maps it to 
      # HTTP_AUTHORIZATION.</strong>
      #
      # If the user is successfuly authenticated the resulting token is 
      # stored on REMOTE_USER into the enviroment. (We didn't want to couple it with session)
      def call(env)
        request = Request.new(env)
        
        if(request.provided? and request.is_wrap?)
          return unauthorized('WRAP') unless token_handler.valid?(request.token)
          env['REMOTE_USER'] = token_handler.parse(request.token)
        end  
        
        return @app.call(env)
      end
    
      # Returns a singleton instance of the SimpleWebToken::SimpleWebTokenHandler based on 
      # the options provided when initializing the middleware.
      def token_handler
        @token_handler ||= SimpleWebToken::SimpleWebTokenHandler.new(@opts)
      end
      
      # Internal class used to parse the current request based on 
      # the enviroment parameters.
      class Request < Rack::Auth::AbstractRequest
        def initialize(env)
          super(env)
        end
   
        # Returns a value indicating whether the Authentication Scheme sent by 
        # the user is WRAP.
        def is_wrap?
          self.scheme == :wrap
        end
        
        # Returns the token contained inside the access_token parameter
        # on the Authorization header, when it's using the WRAP Scheme.
        def token
          CGI.unescape(self.params[/access_token=([^&]+)/, 1])
        end
      end
    end
  end
end