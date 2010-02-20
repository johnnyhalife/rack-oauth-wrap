module SimpleWebToken
  # Handler for parsing, validating and creating (soon) Simple Web Tokens
  # as it stated by the protocol under development of the IEFT v0.9.5.1.
  class SimpleWebTokenHandler
    attr_accessor :shared_secret, :trusted_issuers, :audiences 
    
    # Creates a new instance of the SimpleWebTokenHandler.
    #
    # Valid options include:
    #
    # -__:shared_secret__ the HMAC:SHA256 key shared between parties.
    # -__:trusted_issuers__ the URI(s) of the issuers to be validated on the Issue value of the token.
    # -__:audiences__ the URI(s) of the audiences (apps) to be validated on the Audience value of the token.
    #
    # __Only :shared_secret__ is required, the other values aren't present then no check 
    # is performed.
    def initialize(opts = {})
      raise InvalidOption, :shared_secret unless opts[:shared_secret]
      self.shared_secret = opts[:shared_secret]
      self.trusted_issuers = opts[:trusted_issuers]
      self.audiences = opts[:audiences]
    end
    
    # Validates the signature by doing a symmetric signature comparison,
    # between the value sent as HMACSHA256 on the token and the generated
    # using the shared_key provided.
    def valid_signature?(token)
      return false unless token =~ /&HMACSHA256=(.*)$/
      original_signature = CGI.unescape(token[/&HMACSHA256=(.*)$/, 1])
      bare_token = token.gsub(/&HMACSHA256=(.*)$/, '')
      signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(shared_secret)).update(bare_token.toutf8).digest).strip
      return original_signature == signature
    end
  
    # Returns a value indicating whether the __Issuer__ value of the token 
    # is contained on the trusted_issuer list for the application.
    def valid_issuer?(token)
      issuer = token[/&?Issuer=([^&]+)/, 1]
      [trusted_issuers].flatten.include?(CGI.unescape(issuer))
    end
  
    # Returns a value indicating whether the __Audience__ value of the token 
    # is contained on the audiences list of the application.
    def valid_audience?(token)
      audience = token[/&?Audience=([^&]+)/, 1]
      [audiences].flatten.include?(CGI.unescape(audience))
    end
  
    # Returns a value indicating whether the __ExpiresOn__ value of the token 
    # is older than now.
    def expired?(token)
      expires_on = token[/&?ExpiresOn=([^&]+)/, 1]
      expires_on.to_i < Time.now.to_i
    end
    
    # Returns a value indicating whether the token is valid, the calculation
    # is done as the sum of all the other validations (when values for checking are provided)
    def valid?(token)
      valid = valid_signature?(token)
      valid &&= valid_issuer?(token) if (trusted_issuers)
      valid &&= valid_audience?(token) if (audiences)
      valid &&= !expired?(token)
      return valid
    end
    
    # Returns a key-value pair (hash) with the token values parsed. 
    #
    # __NOTE__: multi-valued claims (provided as comma separated values, 
    # like checkboxes on HTML forms) are returned like arrays.
    def parse(token)
      raise InvalidToken unless valid?(token)
      token.split('&').map{|p| p.split('=') } \
                      .inject({}){|t, i| t.merge!(CGI.unescape(i[0]) => value_for(CGI.unescape(i[1])))}
    end
    
    private 
      # Returns an array if the value is multi-valued 
      # else returns a the value plain.
      def value_for(value)
        values = value.split(',').map{|i| i.strip}
        return values.size == 1 ? values.first() : values
      end
  end
end