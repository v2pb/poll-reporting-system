<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('times', function (Blueprint $table) {
            $table->id();
            $table->string('time_id');
            $table->string('time_name');
            $table->string('ac');
            $table->string('district_id')->nullable();
            $table->boolean('is_active')->default(true);
            $table->string('created_by');
            $table->string('updated_by')->nullable();
            $table->unique(['time_name', 'ac']);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('times');
    }
};
