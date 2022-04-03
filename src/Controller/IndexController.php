<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class IndexController extends AbstractController
{
    /**
     * Hello world
     *
     * @Route(
     *  '/',
     *  methods={"GET"}
     * )
     */
    public function helloWord(Request $request): Response
    {
        return new Response('<h1>Hello World</h1>');
    }

    /**
     * Hello world a quelquun
     *
     * @Route('/{name}', name="hello", methods={"GET"})
     */
    public function hello(Request $request, string $name): Response
    {
        return new Response("<h1>Hello $name </h1>");
    }
}
