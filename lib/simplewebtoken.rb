$LOAD_PATH.unshift(File.dirname __FILE__)

require 'cgi'
require 'base64'
require 'hmac/sha2'

require 'swt/exceptions'
require 'swt/simple_web_token_handler'
