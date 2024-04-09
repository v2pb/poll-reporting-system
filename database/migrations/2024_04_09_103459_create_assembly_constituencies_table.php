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
        Schema::create('assembly_constituencies', function (Blueprint $table) {
            $table->id();
            $table->string('ac_id')->unique(); //unique ac code
            $table->string('ac_name');
            $table->string('state_code')->default('18'); // 18 for Assam
            $table->boolean('status')->default(true);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('assembly_constituencies');
    }
};
