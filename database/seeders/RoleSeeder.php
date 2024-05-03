<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class RoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        DB::table('roles')->insert([
            [
                'role_id' => 100,
                'role_name' => 'Admin',
                'status' => true,
            ],
            [
                'role_id' => 200,
                'role_name' => 'User',
                'status' => true,
            ],
            [
                'role_id' => 300,
                'role_name' => 'Monitoring Role',
                'status' => true,
            ]
        ]);

    }
}
