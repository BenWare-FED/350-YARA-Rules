import "pe"

rule matchesDasuwerugwuerwq
{
        meta: 
            description= "Finds files that are similar to the dasuwerugwuerwq.exe file."
            author="Benjamin McKeever"
            date="2025-10-03"
            threatfamily="Thug Lyfe"

        strings:
            $thuglyfe = "thug.lyfe"

        condition:
            $thuglyfe
}

rule matchesSimplecalc.exe
{
        meta:
                description= "Identifies a file that uses the same suspect malicous code as Simplecalc.exe."
                author="Benjamin Ware"
                date="2025-10-04"
                threatfamily="Thug Lyfe"
        
        strings:
                $thuglyfe = "165.73.244.11/installers"

        condition:
                $thuglyfe
}
//next rule starts here
