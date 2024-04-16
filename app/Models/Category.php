<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Category extends Model
{
    use HasFactory;
    protected $guarded = [];

    public function district()
    {
        return $this->belongsTo(District::class, 'district_id', 'district_id');
    }

    

    public function acDetails()
    {
        return $this->belongsTo(AssemblyConstituency::class, 'ac', 'ac_id');
    }
}
