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
        Schema::create('poll_reports', function (Blueprint $table) {
            $table->id();
            $table->string('category');
            $table->string('two_hourly')->nullable(); //required only if category is selecteda as: poll percentage
            $table->string('remarks');
            $table->string('entered_by'); //entered by which user
            // $table->string('status')->default('0');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('poll_reports');
    }
};
