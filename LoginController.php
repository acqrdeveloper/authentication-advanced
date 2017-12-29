<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/';

    /**
     * Create a new controller instance.
     *
     */
    public function __construct()
    {
        $this->middleware(['guest', 'web'])->except('logout');
    }

    public function login(Request $request)
    {
        $credentials = $request->only(['email', 'password']);
        $rememberme = $request->has('remember') ? true : false;

        if ($this->guard()->attempt($credentials, $rememberme)) {

            if (auth()->once($credentials)) {

                switch (auth()->user()->status) {
                    case 'I':
                        $this->guard()->logout();
                        $request->session()->invalidate();
                        return redirect()->to('login')->withInput()->withErrors('Your session has expired because your account is deactivated.');
                        break;
                    default:

                        $request->session()->regenerate();
                        $this->clearLoginAttempts($request);

                        // create role session
                        session(['role_superadmin' => ["name" => "Alex Christian", "email" => "aquispe.developer@gmail.com", "role" => "superadmin"]]);

                        // redirect false
                        return $this->authenticated($request, $this->guard()->user()) ?: $this->redirectTo;
                        break;
                }
            }
        }

        return redirect()->back()->withInput()->withErrors(trans('auth.failed'));
    }

    public function logout(Request $request)
    {
        $this->guard()->logout();
        $request->session()->invalidate();
        return redirect()->to('login');
    }
}
