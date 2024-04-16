<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class PollReport extends Model
{
    use HasFactory;
    protected $guarded = [];

    public function userDetail()
    {
        return $this->belongsTo(User::class, 'entered_by', 'phone');
    }

    public function categoryDetail() //link with categories table
    {
        return $this->belongsTo(Category::class, 'category', 'category_id');
    }

    public function timeDetail() //link with times table if not null
    {
        return $this->belongsTo(Time::class, 'two_hourly', 'time_id');
    }
}
