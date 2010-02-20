module SimpleWebToken
  class InvalidOption < StandardError
    def initialize(missing_option)
      super("You did not provide one of the required parameters. Please provide the :#{missing_option}.")
    end
  end
  
  class InvalidToken < StandardError
    def initialize
      super("The token you are trying to parse is invalid. Cannot parse invalid Tokens")
    end
  end
end
