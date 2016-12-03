<?php
/**
 * OAuth2 controller.
 * Used for authentication of api calls using JWT.
 *
 * @package api-framework
 * @author CurlyTailed Buffalo
 * @credit  Martin Bean <martin@martinbean.co.uk>
 */
 
class DeviceController extends AbstractController
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
        $this->post($request);
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
            case 3:
                if($request->parameters['token']){
                    echo "shouldnt be running";
                    $thetoken = urldecode($request->parameters['token']);
                    $verified = $this->checkBearerToken($thetoken);
                } else {
                    echo "should be running";
                    $verified = $this->checkBearerToken();
                }
                if($verified){
                    
                    echo "Verified...";
                    $post_type = filter_var($request->url_elements[1], FILTER_SANITIZE_STRING);
                    $device_type = filter_var($request->url_elements[2], FILTER_SANITIZE_STRING);
                    
                    if ($device_type == "light_bulb"){
                        echo "Light bulb type...";
                        $posted = array(
                            'device_id' => $request->parameters['device_id'],
                            'device_attr' => $request->parameters['device_attr'],
                            'device_value' => $request->parameters['device_value'],
                            'token' => $thetoken
                        );
                        if($this->sanitizeLightBulb($posted)){
                            $command = $this->sanitizeLightBulb($posted);
                            echo "Input sanitized..." . $command;
                            if($this->runShellCommand($command)){
                                echo "Shell Run...";
                                return true;
                            }
                        }
                            
                    }
                    
                }
                return false;
            break;
        }
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
    
    protected function runShellCommand($comm)
    {
        
        exec($comm, $out, $err);
        //$json[0] = ($err);
        //$json[1] = ($out);
        return true;
        
    }
    
    protected function sanitizeLightBulb($posted){
        
        if(isset($posted['device_id']) && isset($posted['device_value']) && isset($posted['device_attr'])){
            if ($debug) { echo "Required data found in query..."; }
            $dev = urldecode($dev);
            $dev = filter_var($posted['device_id'], FILTER_SANITIZE_STRING);
            if($posted['device_value'] == "on" || $posted['device_value'] == "off" || $posted['device_value'] == "On" || $posted['device_value'] == "Off"){
                $val = filter_var($posted['device_value'], FILTER_SANITIZE_STRING);
            }else{
                $val = filter_var($posted['device_value'], FILTER_VALIDATE_FLOAT);
            }
            $attr = filter_var($posted['device_attr'], FILTER_SANITIZE_STRING);
                         
            if ($debug) { echo "Data has been sanitized and validated..."; }
                             
        }
                        
        if ($debug) { echo "Fixing device name..."; }
        $dev = trim(strtolower($dev));
        $dev = str_replace('the', '', $dev);
        $dev = str_replace('lite', 'light', $dev);
        echo $dev;
        $dev = urlencode(trim($dev));
        echo $dev;
        $dev = str_replace('+', '%20', $dev);
        echo $dev;
        if ($debug) { echo "Final check... ".$dev." - ".$attr." - ".$val; }
                        
        if($dev && $dev != '' && $attr && $attr != '' && $val && $val != ''){
            $command = "/var/www/scripts/runlights.sh ".$dev." ".$attr." ".$val;
            return $command;
        }
        
        return false;
    
    }
    protected function checkBearerToken($secondary = false)
    {
        if($secondary){
            $token = $secondary;
        }else{
            $headers = apache_request_headers();
        
            $temp = explode(' ', $headers['Authorization']);
            $token = $temp[1];
        }
        $sSecret = (file_get_contents($this->secret_file));
        $user_jwt = JWT::decode($token, $sSecret);

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
            #echo $stored['client_id'] . ' = ' . $user_jwt->data->client_id;
            
            if ( hash_equals($stored['client_id'], crypt($user_jwt->data->client_id, $stored['client_id'])) ) {
                $cidcheck = true;
            }
            if ( hash_equals($stored['client_secret'], crypt($user_jwt->data->client_secret, $stored['client_secret'])) ) {
                $secretcheck = true;
            }
            if($cidcheck && $secretcheck){
                return true;
            }
        }
        
        return false;
    }
    
}