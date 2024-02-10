<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: UserRepository::class)]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $fullname = null;

    #[ORM\OneToMany(targetEntity: ClipboardData::class, mappedBy: 'User', orphanRemoval: true)]
    private Collection $clipboardData;

    #[ORM\Column]
    private ?\DateTimeImmutable $createdAt = null;

    public function __construct()
    {
        $this->clipboardData = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getFullname(): ?string
    {
        return $this->fullname;
    }

    public function setFullname(string $fullname): static
    {
        $this->fullname = $fullname;

        return $this;
    }

    /**
     * @return Collection<int, ClipboardData>
     */
    public function getClipboardData(): Collection
    {
        return $this->clipboardData;
    }

    public function addClipboardData(ClipboardData $clipboardData): static
    {
        if (!$this->clipboardData->contains($clipboardData)) {
            $this->clipboardData->add($clipboardData);
            $clipboardData->setUser($this);
        }

        return $this;
    }

    public function removeClipboardData(ClipboardData $clipboardData): static
    {
        if ($this->clipboardData->removeElement($clipboardData)) {
            // set the owning side to null (unless already changed)
            if ($clipboardData->getUser() === $this) {
                $clipboardData->setUser(null);
            }
        }

        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeImmutable $createdAt): static
    {
        $this->createdAt = $createdAt;

        return $this;
    }
}
