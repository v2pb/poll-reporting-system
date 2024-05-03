<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Validator;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //! Name rule
        Validator::extend('name_rule', function ($attribute, $value, $parameters, $validator) {
            return preg_match('/^[A-Za-z ]+$/', $value);
        });
        Validator::replacer('name_rule', function ($message, $attribute, $rule, $parameters) {
            return str_replace(':attribute', $attribute, 'The ' . $attribute . ' may only contain letters and spaces.');
        });

        //! Phone rule
        Validator::extend('phone_rule', function ($attribute, $value, $parameters, $validator) {
            // return preg_match('/^\d{10}$/', $value);
            return preg_match('/^[0-9]{10}$/', $value);
        });
        Validator::replacer('phone_rule', function ($message, $attribute, $rule, $parameters) {
            return str_replace(':attribute', $attribute, 'The ' . $attribute . ' may only contain 10 digits.');
        });
        
        //! Password rule
        Validator::extend('password_rule', function ($attribute, $value, $parameters, $validator) {
            return preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$/', $value);
        });
        Validator::replacer('password_rule', function ($message, $attribute, $rule, $parameters) {
            return str_replace(':attribute', $attribute, 'The ' . $attribute . ' may only contain letters and spaces.');
        });

        //! Remarks rule
        Validator::extend('remarks_rule', function ($attribute, $value, $parameters, $validator) {
            return preg_match('/^[a-zA-Z0-9\s,.()\-\!\%\&]+$/', $value);
        });
        Validator::replacer('remarks_rule', function ($message, $attribute, $rule, $parameters) {
            return str_replace(':attribute', $attribute, 'The ' . $attribute . ' may only contain letters, spaces, numbers, commas, colons, hyphen, brackets and dots only!');
        });
    }
}
