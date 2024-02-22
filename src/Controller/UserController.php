<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Routing\Annotation\Route;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class UserController extends AbstractController
{

    private $userRepository;

    private $serializerInterface;

    private $jwtManager;

    private $tokenStorageInterface;

    private $entityManagerInterface;
    

    public function __construct(UserRepository $userRepository, SerializerInterface $serializerInterface, JWTTokenManagerInterface $jwtManager, TokenStorageInterface $tokenStorageInterface, EntityManagerInterface $entityManagerInterface)
    {
        $this->userRepository = $userRepository;

        $this->serializerInterface = $serializerInterface;

        $this->jwtManager = $jwtManager;

        $this->tokenStorageInterface = $tokenStorageInterface;

        $this->entityManagerInterface = $entityManagerInterface;
        
    }



    #[Route('/api/user-management/users', name: 'users', methods:['GET'])]
    public function getUserList(): JsonResponse
    {
        $users = $this->userRepository->findAll();
        $jsonUserList = $this->serializerInterface->serialize($users, 'json', ['groups'=>'getUsers']);

        if ($users) {
            # code...
            return new JsonResponse($jsonUserList, JsonResponse::HTTP_OK, [], true);
            
        }else{
            return new JsonResponse(['message'=>'No data found!'], JsonResponse::HTTP_NOT_FOUND, []);
        }

    }


    #[Route('/user-management/users/{id}', name:'user', methods:['GET'])]
    public function getUserDetails( $id): JsonResponse
    {
        $user = $this->userRepository->find($id);
        if(!$user){
            return new JsonResponse(['message'=>'No user found with that ID.'], JsonResponse::HTTP_NOT_FOUND, []);
        }
        $jsonUser = $this->serializerInterface->serialize($user, 'json', ['groups'=>'getUsers']);

        return new JsonResponse($jsonUser, JsonResponse::HTTP_OK, [], true);
    }

    #[Route('/user-management/users/{id}', name: 'updateUser', methods:['PUT'])]
    public function updateProfileUser(User $user, Request $request, UserPasswordHasherInterface $userPasswordHasherInterface): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        /*$decodedJwtToken = $this->jwtManager->decode($this->tokenStorageInterface->getToken());
        $userEmailInToken = $decodedJwtToken['username'];*/

        
        $fullname = $data['fullname'];
        $password = $data['password'];
        
        if (!$user) {
            return new JsonResponse([
                'message'=>'That user does not exist. Please, Create an account.'
            ], 400);
        }
            //validation
            if (strlen($password) < 8) {
                return new JsonResponse([
                    'message'=>'The password must be at least 8 characters long'
                ], JsonResponse::HTTP_BAD_REQUEST, []);
            }

            $limit = 3;
            if (strlen($fullname) < $limit) {
                return new JsonResponse([
                    'message'=>'Fullname must be at least 3 characters long.'
                ], JsonResponse::HTTP_BAD_REQUEST, []);
            }

            //validation

            /*if ($user->getEmail() !== $userEmailInToken) {
                return new JsonResponse([
                    'message'=>'Unauthorized'
                ], JsonResponse::HTTP_UNAUTHORIZED, [], true);
            }*/

            
            if ($userPasswordHasherInterface->isPasswordValid($user, $password)) {
                $user
                    ->setFullname($fullname);

                $this->entityManagerInterface->persist($user);
                $this->entityManagerInterface->flush();

                return new JsonResponse([
                    'message'=>'User updated successfully.',

                ], JsonResponse::HTTP_OK, []);
            }else{
                return new JsonResponse([
                    'message'=>'Invalid password.'
                ], JsonResponse::HTTP_UNAUTHORIZED, []);
            }

        
    }

    #[Route('/user-management/users/{id}', name:'updateUserPassword', methods:['PUT'])]
    public function updateUserPassword(User $user, Request $request, UserPasswordHasherInterface $userPasswordHasherInterface): JsonResponse
    {
        $dataFromRequest = json_decode($request->getContent(), true);

        $decodedJwtToken = $this->jwtManager->decode($this->tokenStorageInterface->getToken());
        $userEmailInToken = $decodedJwtToken['username'];

        $email = $dataFromRequest['email'];
        $lastPassword = $dataFromRequest['lastPassword'];
        $newPassword = $dataFromRequest['newPassword'];

        if (empty($userEmailInToken)) {
            # code...
            return new JsonResponse([
                'message'=>'You must be connected to change your password.'
            ], JsonResponse::HTTP_UNAUTHORIZED, []);
        }

        if ($email !== $userEmailInToken) {
            return new JsonResponse([
                'message'=>'Access Denied.'
            ], JsonResponse::HTTP_UNAUTHORIZED, []);
        }

        if ($user->getPassword() !== $lastPassword) {
            return new JsonResponse([
                'message'=>'Incorrecte Password.'
            ], JsonResponse::HTTP_UNAUTHORIZED, []);
        }

        if ($newPassword === $email) {
            # code...
            return new JsonResponse([
                'message'=>'Your password can be your email, Please change it.'
            ],JsonResponse::HTTP_BAD_REQUEST, [], true);
        }

        $hashPassword = $userPasswordHasherInterface->hashPassword(
            $user,
            $newPassword
        );
        
        $user->setPassword($hashPassword);

        $this->entityManagerInterface->persist($user);
        $this->entityManagerInterface->flush();

        return new JsonResponse([
            'message'=>'Password updated successfully.'
        ], JsonResponse::HTTP_OK, [], true);

    }

    #[Route('/user-management/users', name:'newUser', methods:['POST'])]
    public function newUser(Request $request, UserPasswordHasherInterface $userPasswordHasherInterface): JsonResponse
    {
        $dataFromRequest = json_decode($request->getContent(), true);

        $email = $dataFromRequest['email'];
        $fullname = $dataFromRequest['fullname'];
        $password = $dataFromRequest['password'];

        if($password === $email){
            return new JsonResponse([
                'message'=>'Your password can be your email, Please change it.'
            ], JsonResponse::HTTP_BAD_REQUEST, []);
        }

        if(strlen($password) < 8){
            return new JsonResponse([
                'message'=>'Password length must greather than 8 characters.'
            ], JsonResponse::HTTP_BAD_REQUEST, []);
        }

        if(empty($dataFromRequest)){
            return new JsonResponse([
                'message'=>'No data in the request.'
            ], JsonResponse::HTTP_NO_CONTENT, []);
        }
        $newUser = new User();
        $hashPassword = $userPasswordHasherInterface->hashPassword($newUser, $password);

        $newUser->setEmail($email)
            ->setFullname($fullname)
            ->setPassword($hashPassword);

        $this->entityManagerInterface->persist($newUser);
        $this->entityManagerInterface->flush();

        return new JsonResponse([
            'message'=>'Your compte is created successfully.'
        ], JsonResponse::HTTP_OK, []);
    }

    #[Route('/admin-management/admins', name:'newAdmin', methods:['POST'])]
    public function newAdmin(Request $request, UserPasswordHasherInterface $userPasswordHasherInterface): JsonResponse
    {
        $dataFromRequest = json_decode($request->getContent(), true);

        $email = $dataFromRequest['email'];
        $fullname = $dataFromRequest['fullname'];
        $roles = ['ROLE_USER', 'ROLE_ADMIN'];
        $password = $dataFromRequest['password'];

        if (empty($dataFromRequest)) {
            # code...
            return new JsonResponse([
                'message'=>'No data in the request.'
            ], JsonResponse::HTTP_NO_CONTENT, []);
        }

        if(strlen($password) < 8){
            return new JsonResponse([
                'message'=>'Password length must greather than 8 characters.'
            ], JsonResponse::HTTP_BAD_REQUEST, []);
        }

        if ($password === $email) {
            # code...
            return new JsonResponse([
                'message'=>'Your password can not be your email, Please change it.'
            ], JsonResponse::HTTP_BAD_REQUEST, []);
        }

        $newAdmin = new User();
        $hashPassword = $userPasswordHasherInterface->hashPassword(
            $newAdmin,
            $password
        );

        $newAdmin->setEmail($email)
            ->setFullname($fullname)
            ->setRoles($roles)
            ->setPassword($hashPassword);
        
        $this->entityManagerInterface->persist($newAdmin);
        $this->entityManagerInterface->flush();

        return new JsonResponse([
            'message'=> 'Admin added successfully.'
        ], JsonResponse::HTTP_OK, [], true);
    }

    #[Route('/user-management/users/{id}', name: 'deleteUser', methods:['DELETE'])]
    public function deleteUser(User $user): JsonResponse
    {
        $decodedJwtToken = $this->jwtManager->decode($this->tokenStorageInterface->getToken());
        $userEmailInToken = $decodedJwtToken['username'];

        if ($userEmailInToken !== $user->getEmail()) {
            # code...
            return new JsonResponse([
                'message'=>'Access Denied.'
            ], JsonResponse::HTTP_UNAUTHORIZED, [], true);
        }

        if (!$user) {
            # code...
            return new JsonResponse([
                'message'=>'User does not exist.'
            ], JsonResponse::HTTP_NOT_FOUND, [], true);
        }

        $this->entityManagerInterface->remove($user);
        $this->entityManagerInterface->flush();

        return new JsonResponse([
            'message'=>'User deleted successfully.'
        ], JsonResponse::HTTP_NO_CONTENT, [], true);
    }
}
