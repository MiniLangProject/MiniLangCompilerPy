namespace Demo
  class Vault
    private static function secret() returns int
      return 42
    end function

    static function reveal() returns int
      return Demo.Vault.secret()
    end function
  end class
end namespace

function main(args)
  if Demo.Vault.reveal() != 42 then return 1 end if
  print "[OK] qualified private static call"
  return 0
end function
