<?php
/**
 * OAuth2 controller.
 * Used for authentication of api calls using JWT.
 *
 * @package api-framework
 * @author CurlyTailed Buffalo
 * @credit  Martin Bean <martin@martinbean.co.uk>
 */
 
class Oauth2Controller extends AbstractController
{
    /**
     * Credentials file.
     *
     * @var variable type
     */
    protected $secret_file = '../../../passwords/apisecret.txt'; 
    protected $creds_file = '../../../passwords/apicredentials.txt';
    
    /**
     * GET method.
     * 
     * @param  Request $request
     * @return string
     */
    public function get($request)
    {
        /*switch (count($request->url_elements)) {
            case 1:
                return true;
            break;
            case 2:
                return ;
            break;
        }*/
    }
    
    /**
     * POST action.
     *
     * @param  $request
     * @return string
     */
    public function post($request)
    {
        
        $this->checkForHashEquals();
        switch (count($request->url_elements)) {
            case 1:
                //header('HTTP/1.1 201 Created');
                //header('Location: /news/'.$id);
                return null;
            break;
            case 2:
                
                $post_type = filter_var($request->url_elements[1], FILTER_SANITIZE_STRING);
                if ($post_type == "new"){
                    $posted = array(
                        'username' => $request->parameters['username'],
                        'password' => $request->parameters['password'],
                        'client_id' => $request->parameters['client_id'],
                        'client_secret' => $request->parameters['client_secret'],
                        'published' => date('c')
                    );
                    
                    $credentials = (file_get_contents($this->creds_file));
                    $ctemp = explode('\n\r', $credentials);
                    foreach($ctemp as $usert){
                        $user = explode(':', $usert);
                        $stored = [
                            'username' => trim($user[0]),
                            'password' => trim($user[1]),
                            'client_id' => trim($user[2]),
                            'client_secret' => trim($user[3])
                        ];
                       
                        if ($stored['username'] == $posted['username'] && $this->checkGetTokenCredentials($posted, $stored)){
                            $jwt = new JWT();
                            $data = [
                                    'iat'  => $posted['published'],         // Issued at: time when the token was generated
                                    'data' => [                  // Data related to the logged user you can set your required data
                                        'client_id'   => $posted['client_id'],
                                        'client_secret' => $posted['client_secret']
                                    ]
                                ];
                            $sSecret = (file_get_contents($this->secret_file));
                            
                            return JWT::encode($data, $sSecret);
                        }
                    }
                }
            break;
        }
    }

    /**
     * Checks posted credentials agaist the stored credentials.
     *
     * @param  $posted, $hashed
     * @return boolean
     */
    protected function checkGetTokenCredentials($posted, $hashed)
    {
        $passcheck = false;
        $cidcheck = false;
        $secretcheck = false;
        
        if ( hash_equals($hashed['password'], crypt($posted['password'], $hashed['password'])) ) {
          $passcheck = true;
        }
        if ( hash_equals($hashed['client_id'], crypt($posted['client_id'], $hashed['client_id'])) ) {
          $cidcheck = true;
        }
        if ( hash_equals($hashed['client_secret'], crypt($posted['client_secret'], $hashed['client_secret'])) ) {
          $secretcheck = true;
        }
        
        if($passcheck && $cidcheck && $secretcheck){
            return true;
        }
        
        return false;
    }
    
    /**
     * Creates a hash from the inputted value. Uses mcrpyt Blowfish.
     *
     * @param  $raw_input
     * @return string
     */
    protected function createPasswordHash($raw_input)
    {
        $cost = 6;
        $salt = strtr(base64_encode(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM)), '+', '.');
        $salt = sprintf("$2a$%02d$", $cost) . $salt;
        $hash = crypt($raw_input, $salt);
        return $hash;
    }
    
    
}