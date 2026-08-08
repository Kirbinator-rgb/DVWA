<?php declare(strict_types=1);

namespace Src;

use OpenApi\Attributes as OAT;

/*
#[OA\Schema()]
enum UserLevel {
    case ADMIN;
    case USER;
}
*/
#[OAT\Schema()]
final class User
{
    #[OAT\Property(type: 'integer', example: 1)]
    public int $id;

    #[OAT\Property(type: "string", example: "fred")]
    public string $name;

    #[OAT\Property(type: 'integer', example: 1)]
    public int $level;

	public string $password;

	function __construct ($id, $name, $level, $password) {
		if (is_null ($id)) {
			$id = mt_rand(50,100);
		}
		$this->id = $id;
		$this->name = $name;
		$this->level = $level;
		$this->password = $password;
	}

	public function toArray($version) {
		// The password hash is never part of a user representation, at any version. Keeping an
		// older version alive is a compatibility decision; it is not a licence for that version
		// to disclose more than the current one. v1 used to return the stored hash to any
		// unauthenticated caller who asked for it, so every account was offline-crackable by
		// changing a single digit in the URL -- the retired version was doing the leaking while
		// the maintained one looked clean.
		//
		// A response should carry the fields the caller needs and nothing else, decided here on
		// the server rather than left to the client to filter.
		return array (
			"id" => $this->id,
			"name" => $this->name,
			"level" => $this->level,
		);
	}
}

#[OAT\Schema(required: ['level', 'name'])]
final class UserAdd
{
    #[OAT\Property(example: "fred")]
    public string $name;

    #[OAT\Property(type: 'integer', example: 1)]
    public string $level;
}

#[OAT\Schema(required: ['name'])]
final class UserUpdate
{
    #[OAT\Property(example: "fred")]
    public string $name;
}
