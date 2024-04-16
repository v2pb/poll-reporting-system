<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ApiController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::middleware('admin')->group(function () {
    Route::post('admin_update', [ApiController::class, 'admin_update']);
    Route::post('get_admin_data', [ApiController::class, 'get_admin_data']);


    Route::post('register_admin', [ApiController::class, 'register_admin']);
    Route::post('update_admin', [ApiController::class, 'update_admin']);

    //User Registration Form 
    Route::post('register_user', [ApiController::class, 'register_user']);
    Route::post('get_user_data', [ApiController::class, 'get_user_data']);
    Route::post('update_user', [ApiController::class, 'update_user']);
    Route::post('get_register_users_list', [ApiController::class, 'get_register_users_list']);

    //Category Master Form
    Route::post('register_category', [ApiController::class, 'register_category']);
    Route::post('get_register_categories_list', [ApiController::class, 'get_register_categories_list']);
    Route::post('get_category_details', [ApiController::class, 'get_category_details']);
    Route::post('update_category', [ApiController::class, 'update_category']);

    //Time Master Form
    Route::post('register_time', [ApiController::class, 'register_time']);
    Route::post('get_register_times_list', [ApiController::class, 'get_register_times_list']);
    Route::post('get_time_details', [ApiController::class, 'get_time_details']);
    Route::post('update_time', [ApiController::class, 'update_time']);

    //Poll Status Reports
    Route::post('view_poll_reports', [ApiController::class, 'view_poll_reports']);
});

Route::middleware('user')->group(function () {
    Route::post('create_poll_report', [ApiController::class, 'create_poll_report']);
    Route::post('display_poll_status_reports', [ApiController::class, 'display_poll_status_reports']);
    Route::post('get_dropdown_categories', [ApiController::class, 'get_dropdown_categories']);
    Route::post('get_dropdown_times', [ApiController::class, 'get_dropdown_times']);
});

//auth
Route::post('login', [ApiController::class, 'login'])->name('login');