<?php

namespace App\DataFixtures;

use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;

class AppFixtures extends Fixture
{
    public function load(ObjectManager $manager): void
    {
        // $product = new Product();
        // $manager->persist($product);
        $user = new User();
        $user->setEmail("user@gmail.com")
            ->setFullname("user")
            ->setPassword("userpassword");
        $manager->persist($user);

        $admin = new User();
        $admin->setEmail("admin@gmail.com")
            ->setFullname("admin")
            ->setPassword("adminpassword")
            ->setRoles(["ROLE_USER", "ROLE_ADMIN"]);

        $manager->persist($admin);

        $manager->flush();
    }
}
