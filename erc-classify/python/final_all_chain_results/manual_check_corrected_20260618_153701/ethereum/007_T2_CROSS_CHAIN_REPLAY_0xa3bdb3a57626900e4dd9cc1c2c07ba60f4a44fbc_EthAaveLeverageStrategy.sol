// SPDX-License-Identifier: UNLICENSED
// Flattened source downloaded from Etherscan
// Address: 0xa3bdb3a57626900e4dd9cc1c2c07ba60f4a44fbc
// Contract Name: EthAaveLeverageStrategy



// ============================================================
// FILE: src/leverage/EthAaveLeverageStrategy.sol
// ============================================================
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity ^0.8.26;

import {WETH9} from '@aave-core/dependencies/weth/WETH9.sol';
import {IEthVault} from '@stakewise-core/interfaces/IEthVault.sol';
import {IStrategy} from '../interfaces/IStrategy.sol';
import {IStrategyProxy} from '../interfaces/IStrategyProxy.sol';
import {LeverageStrategy} from './LeverageStrategy.sol';
import {AaveLeverageStrategy} from './AaveLeverageStrategy.sol';

/**
 * @title EthAaveLeverageStrategy
 * @author StakeWise
 * @notice Defines the Aave leverage strategy functionality on Ethereum
 */
contract EthAaveLeverageStrategy is AaveLeverageStrategy {
    /**
     * @dev Constructor
     * @param osToken The address of the OsToken contract
     * @param assetToken The address of the asset token contract (e.g. WETH)
     * @param osTokenVaultController The address of the OsTokenVaultController contract
     * @param osTokenConfig The address of the OsTokenConfig contract
     * @param osTokenFlashLoans The address of the OsTokenFlashLoans contract
     * @param osTokenVaultEscrow The address of the OsTokenVaultEscrow contract
     * @param strategiesRegistry The address of the StrategiesRegistry contract
     * @param strategyProxyImplementation The address of the StrategyProxy implementation
     * @param balancerVault The address of the BalancerVault contract
     * @param aavePool The address of the Aave pool contract
     * @param aaveOsToken The address of the Aave OsToken contract
     * @param aaveVarDebtAssetToken The address of the Aave variable debt asset token contract
     */
    constructor(
        address osToken,
        address assetToken,
        address osTokenVaultController,
        address osTokenConfig,
        address osTokenFlashLoans,
        address osTokenVaultEscrow,
        address strategiesRegistry,
        address strategyProxyImplementation,
        address balancerVault,
        address aavePool,
        address aaveOsToken,
        address aaveVarDebtAssetToken
    )
        AaveLeverageStrategy(
            osToken,
            assetToken,
            osTokenVaultController,
            osTokenConfig,
            osTokenFlashLoans,
            osTokenVaultEscrow,
            strategiesRegistry,
            strategyProxyImplementation,
            balancerVault,
            aavePool,
            aaveOsToken,
            aaveVarDebtAssetToken
        )
    {}

    /// @inheritdoc IStrategy
    function strategyId() public pure override returns (bytes32) {
        return keccak256('EthAaveLeverageStrategy');
    }

    /// @inheritdoc LeverageStrategy
    function _claimOsTokenVaultEscrowAssets(
        address vault,
        address proxy,
        uint256 positionTicket,
        uint256 osTokenShares
    ) internal override returns (uint256 claimedAssets) {
        claimedAssets = super._claimOsTokenVaultEscrowAssets(vault, proxy, positionTicket, osTokenShares);
        if (claimedAssets == 0) return 0;

        // convert ETH to WETH
        IStrategyProxy(proxy).executeWithValue(
            address(_assetToken),
            abi.encodeWithSelector(WETH9(payable(address(_assetToken))).deposit.selector),
            claimedAssets
        );
    }

    /// @inheritdoc LeverageStrategy
    function _mintOsTokenShares(
        address vault,
        address proxy,
        uint256 depositAssets,
        uint256 mintOsTokenShares
    ) internal override returns (uint256) {
        IStrategyProxy(proxy).execute(
            address(_assetToken),
            abi.encodeWithSelector(WETH9(payable(address(_assetToken))).withdraw.selector, depositAssets)
        );
        uint256 balanceBefore = _osToken.balanceOf(proxy);
        IStrategyProxy(proxy).executeWithValue(
            vault,
            abi.encodeWithSelector(
                IEthVault(vault).depositAndMintOsToken.selector, proxy, mintOsTokenShares, address(0)
            ),
            depositAssets
        );
        return _osToken.balanceOf(proxy) - balanceBefore;
    }

    /// @inheritdoc LeverageStrategy
    function _transferAssets(address proxy, address receiver, uint256 amount) internal override {
        IStrategyProxy(proxy).execute(
            address(_assetToken), abi.encodeWithSelector(WETH9(payable(address(_assetToken))).withdraw.selector, amount)
        );
        IStrategyProxy(proxy).sendValue(payable(receiver), amount);
    }
}



// ============================================================
// FILE: lib/aave-v3-origin/src/contracts/dependencies/weth/WETH9.sol
// ============================================================
// Copyright (C) 2015, 2016, 2017 Dapphub

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity ^0.8.10;

contract WETH9 {
  string public name = 'Wrapped Ether';
  string public symbol = 'WETH';
  uint8 public decimals = 18;

  event Approval(address indexed src, address indexed guy, uint256 wad);
  event Transfer(address indexed src, address indexed dst, uint256 wad);
  event Deposit(address indexed dst, uint256 wad);
  event Withdrawal(address indexed src, uint256 wad);

  mapping(address => uint256) public balanceOf;
  mapping(address => mapping(address => uint256)) public allowance;

  receive() external payable {
    deposit();
  }

  function deposit() public payable {
    balanceOf[msg.sender] += msg.value;
    emit Deposit(msg.sender, msg.value);
  }

  function withdraw(uint256 wad) public {
    require(balanceOf[msg.sender] >= wad);
    balanceOf[msg.sender] -= wad;
    payable(msg.sender).transfer(wad);
    emit Withdrawal(msg.sender, wad);
  }

  function totalSupply() public view returns (uint256) {
    return address(this).balance;
  }

  function approve(address guy, uint256 wad) public returns (bool) {
    allowance[msg.sender][guy] = wad;
    emit Approval(msg.sender, guy, wad);
    return true;
  }

  function transfer(address dst, uint256 wad) public returns (bool) {
    return transferFrom(msg.sender, dst, wad);
  }

  function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
    require(balanceOf[src] >= wad);

    if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
      require(allowance[src][msg.sender] >= wad);
      allowance[src][msg.sender] -= wad;
    }

    balanceOf[src] -= wad;
    balanceOf[dst] += wad;

    emit Transfer(src, dst, wad);

    return true;
  }
}

/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received.  You must make sure that they, too, receive
or can get the source code.  And you must show them these terms so they
know their rights.

  Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

  For the developers' and authors' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users' and
authors' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

  Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the manufacturer
can do so.  This is fundamentally incompatible with the aim of
protecting users' freedom to change the software.  The systematic
pattern of such abuse occurs in the area of products for individuals to
use, which is precisely where it is most unacceptable.  Therefore, we
have designed this version of the GPL to prohibit the practice for those
products.  If such problems arise substantially in other domains, we
stand ready to extend this provision to those domains in future versions
of the GPL, as needed to protect the freedom of users.

  Finally, every program is threatened constantly by software patents.
States should not allow patents to restrict development and use of
software on general-purpose computers, but in those that do, we wish to
avoid the special danger that patents applied to a free program could
make it effectively proprietary.  To prevent this, the GPL assures that
patents cannot be used to render the program non-free.

  The precise terms and conditions for copying, distribution and
modification follow.

                       TERMS AND CONDITIONS

  0. Definitions.

  "This License" refers to version 3 of the GNU General Public License.

  "Copyright" also means copyright-like laws that apply to other kinds of
works, such as semiconductor masks.

  "The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

  To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

  A "covered work" means either the unmodified Program or a work based
on the Program.

  To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy.  Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

  To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

  An interactive user interface displays "Appropriate Legal Notices"
to the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License.  If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

  1. Source Code.

  The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

  A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

  The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form.  A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

  The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities.  However, it does not include the work's
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work.  For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

  The Corresponding Source need not include anything that users
can regenerate automatically from other parts of the Corresponding
Source.

  The Corresponding Source for a work in source code form is that
same work.

  2. Basic Permissions.

  All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.  The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work.  This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

  You may make, run and propagate covered works that you do not
convey, without conditions so long as your license otherwise remains
in force.  You may convey covered works to others for the sole purpose
of having them make modifications exclusively for you, or provide you
with facilities for running those works, provided that you comply with
the terms of this License in conveying all material for which you do
not control copyright.  Those thus making or running the covered works
for you must do so exclusively on your behalf, under your direction
and control, on terms that prohibit them from making any copies of
your copyrighted material outside their relationship with you.

  Conveying under any other circumstances is permitted solely under
the conditions stated below.  Sublicensing is not allowed; section 10
makes it unnecessary.

  3. Protecting Users' Legal Rights From Anti-Circumvention Law.

  No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

  When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such circumvention
is effected by exercising rights under this License with respect to
the covered work, and you disclaim any intention to limit operation or
modification of the work as a means of enforcing, against the work's
users, your or third parties' legal rights to forbid circumvention of
technological measures.

  4. Conveying Verbatim Copies.

  You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

  You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

  5. Conveying Modified Source Versions.

  You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

    a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.

    b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under section
    7.  This requirement modifies the requirement in section 4 to
    "keep intact all notices".

    c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy.  This
    License will therefore apply, along with any applicable section 7
    additional terms, to the whole of the work, and all its parts,
    regardless of how they are packaged.  This License gives no
    permission to license the work in any other way, but it does not
    invalidate such permission if you have separately received it.

    d) If the work has interactive user interfaces, each must display
    Appropriate Legal Notices; however, if the Program has interactive
    interfaces that do not display Appropriate Legal Notices, your
    work need not make them do so.

  A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation's users
beyond what the individual works permit.  Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

  6. Conveying Non-Source Forms.

  You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the
machine-readable Corresponding Source under the terms of this License,
in one of these ways:

    a) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by the
    Corresponding Source fixed on a durable physical medium
    customarily used for software interchange.

    b) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by a
    written offer, valid for at least three years and valid for as
    long as you offer spare parts or customer support for that product
    model, to give anyone who possesses the object code either (1) a
    copy of the Corresponding Source for all the software in the
    product that is covered by this License, on a durable physical
    medium customarily used for software interchange, for a price no
    more than your reasonable cost of physically performing this
    conveying of source, or (2) access to copy the
    Corresponding Source from a network server at no charge.

    c) Convey individual copies of the object code with a copy of the
    written offer to provide the Corresponding Source.  This
    alternative is allowed only occasionally and noncommercially, and
    only if you received the object code with such an offer, in accord
    with subsection 6b.

    d) Convey the object code by offering access from a designated
    place (gratis or for a charge), and offer equivalent access to the
    Corresponding Source in the same way through the same place at no
    further charge.  You need not require recipients to copy the
    Corresponding Source along with the object code.  If the place to
    copy the object code is a network server, the Corresponding Source
    may be on a different server (operated by you or a third party)
    that supports equivalent copying facilities, provided you maintain
    clear directions next to the object code saying where to find the
    Corresponding Source.  Regardless of what server hosts the
    Corresponding Source, you remain obligated to ensure that it is
    available for as long as needed to satisfy these requirements.

    e) Convey the object code using peer-to-peer transmission, provided
    you inform other peers where the object code and Corresponding
    Source of the work are being offered to the general public at no
    charge under subsection 6d.

  A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

  A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal, family,
or household purposes, or (2) anything designed or sold for incorporation
into a dwelling.  In determining whether a product is a consumer product,
doubtful cases shall be resolved in favor of coverage.  For a particular
product received by a particular user, "normally used" refers to a
typical or common use of that class of product, regardless of the status
of the particular user or of the way in which the particular user
actually uses, or expects or is expected to use, the product.  A product
is a consumer product regardless of whether the product has substantial
commercial, industrial or non-consumer uses, unless such uses represent
the only significant mode of use of the product.

  "Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to install
and execute modified versions of a covered work in that User Product from
a modified version of its Corresponding Source.  The information must
suffice to ensure that the continued functioning of the modified object
code is in no case prevented or interfered with solely because
modification has been made.

  If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information.  But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

  The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or updates
for a work that has been modified or installed by the recipient, or for
the User Product in which it has been modified or installed.  Access to a
network may be denied when the modification itself materially and
adversely affects the operation of the network or violates the rules and
protocols for communication across the network.

  Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

  7. Additional Terms.

  "Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law.  If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

  When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it.  (Additional permissions may be written to require their own
removal in certain cases when you modify the work.)  You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

  Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders of
that material) supplement the terms of this License with terms:

    a) Disclaiming warranty or limiting liability differently from the
    terms of sections 15 and 16 of this License; or

    b) Requiring preservation of specified reasonable legal notices or
    author attributions in that material or in the Appropriate Legal
    Notices displayed by works containing it; or

    c) Prohibiting misrepresentation of the origin of that material, or
    requiring that modified versions of such material be marked in
    reasonable ways as different from the original version; or

    d) Limiting the use for publicity purposes of names of licensors or
    authors of the material; or

    e) Declining to grant rights under trademark law for use of some
    trade names, trademarks, or service marks; or

    f) Requiring indemnification of licensors and authors of that
    material by anyone who conveys the material (or modified versions of
    it) with contractual assumptions of liability to the recipient, for
    any liability that these contractual assumptions directly impose on
    those licensors and authors.

  All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10.  If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term.  If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

  If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

  Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions;
the above requirements apply either way.

  8. Termination.

  You may not propagate or modify a covered work except as expressly
provided under this License.  Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

  However, if you cease all violation of this License, then your
license from a particular copyright holder is reinstated (a)
provisionally, unless and until the copyright holder explicitly and
finally terminates your license, and (b) permanently, if the copyright
holder fails to notify you of the violation by some reasonable means
prior to 60 days after the cessation.

  Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

  Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License.  If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

  9. Acceptance Not Required for Having Copies.

  You are not required to accept this License in order to receive or
run a copy of the Program.  Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance.  However,
nothing other than this License grants you permission to propagate or
modify any covered work.  These actions infringe copyright if you do
not accept this License.  Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

  10. Automatic Licensing of Downstream Recipients.

  Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.  You are not responsible
for enforcing compliance by third parties with this License.

  An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations.  If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party's predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

  You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License.  For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

  11. Patents.

  A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based.  The
work thus licensed is called the contributor's "contributor version".

  A contributor's "essential patent claims" are all patent claims
owned or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version.  For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

  Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor's essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

  In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement).  To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

  If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients.  "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient's use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

  If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

  A patent license is "discriminatory" if it does not include within
the scope of its coverage, prohibits the exercise of, or is
conditioned on the non-exercise of one or more of the rights that are
specifically granted under this License.  You may not convey a covered
work if you are a party to an arrangement with a third party that is
in the business of distributing software, under which you make payment
to the third party based on the extent of your activity of conveying
the work, and under which the third party grants, to any of the
parties who would receive the covered work from you, a discriminatory
patent license (a) in connection with copies of the covered work
conveyed by you (or copies made from those copies), or (b) primarily
for and in connection with specific products or compilations that
contain the covered work, unless you entered into that arrangement,
or that patent license was granted, prior to 28 March 2007.

  Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may
otherwise be available to you under applicable patent law.

  12. No Surrender of Others' Freedom.

  If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot convey a
covered work so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you may
not convey it at all.  For example, if you agree to terms that obligate you
to collect a royalty for further conveying from those to whom you convey
the Program, the only way you could satisfy both those terms and this
License would be to refrain entirely from conveying the Program.

  13. Use with the GNU Affero General Public License.

  Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work.  The terms of this
License will continue to apply to the part which is the covered work,
but the special requirements of the GNU Affero General Public License,
section 13, concerning interaction through a network will apply to the
combination as such.

  14. Revised Versions of this License.

  The Free Software Foundation may publish revised and/or new versions of
the GNU General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

  Each version is given a distinguishing version number.  If the
Program specifies that a certain numbered version of the GNU General
Public License "or any later version" applies to it, you have the
option of following the terms and conditions either of that numbered
version or of any later version published by the Free Software
Foundation.  If the Program does not specify a version number of the
GNU General Public License, you may choose any version ever published
by the Free Software Foundation.

  If the Program specifies that a proxy can decide which future
versions of the GNU General Public License can be used, that proxy's
public statement of acceptance of a version permanently authorizes you
to choose that version for the Program.

  Later license versions may give you additional or different
permissions.  However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

  15. Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

  16. Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

  17. Interpretation of Sections 15 and 16.

  If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

                     END OF TERMS AND CONDITIONS

            How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
state the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) <year>  <name of author>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If the program does terminal interaction, make it output a short
notice like this when it starts in an interactive mode:

    <program>  Copyright (C) <year>  <name of author>
    This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, your program's commands
might be different; for a GUI interface, you would use an "about box".

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU GPL, see
<http://www.gnu.org/licenses/>.

  The GNU General Public License does not permit incorporating your program
into proprietary programs.  If your program is a subroutine library, you
may consider it more useful to permit linking proprietary applications with
the library.  If this is what you want to do, use the GNU Lesser General
Public License instead of this License.  But first, please read
<http://www.gnu.org/philosophy/why-not-lgpl.html>.

*/



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IEthVault.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IKeeperRewards} from "./IKeeperRewards.sol";
import {IVaultAdmin} from "./IVaultAdmin.sol";
import {IVaultVersion} from "./IVaultVersion.sol";
import {IVaultFee} from "./IVaultFee.sol";
import {IVaultState} from "./IVaultState.sol";
import {IVaultValidators} from "./IVaultValidators.sol";
import {IVaultEnterExit} from "./IVaultEnterExit.sol";
import {IVaultOsToken} from "./IVaultOsToken.sol";
import {IVaultMev} from "./IVaultMev.sol";
import {IVaultEthStaking} from "./IVaultEthStaking.sol";
import {IMulticall} from "./IMulticall.sol";

/**
 * @title IEthVault
 * @author StakeWise
 * @notice Defines the interface for the EthVault contract
 */
interface IEthVault is
    IVaultAdmin,
    IVaultVersion,
    IVaultFee,
    IVaultState,
    IVaultValidators,
    IVaultEnterExit,
    IVaultOsToken,
    IVaultMev,
    IVaultEthStaking,
    IMulticall
{
    /**
     * @dev Struct for deploying the EthVault contract
     * @param keeper The address of the Keeper contract
     * @param vaultsRegistry The address of the VaultsRegistry contract
     * @param validatorsRegistry The contract address used for registering validators in beacon chain
     * @param validatorsWithdrawals The contract address used for withdrawing validators in beacon chain
     * @param validatorsConsolidations The contract address used for consolidating validators in beacon chain
     * @param consolidationsChecker The contract address used for checking consolidations
     * @param osTokenVaultController The address of the OsTokenVaultController contract
     * @param osTokenConfig The address of the OsTokenConfig contract
     * @param osTokenVaultEscrow The address of the OsTokenVaultEscrow contract
     * @param sharedMevEscrow The address of the shared MEV escrow
     * @param depositDataRegistry The address of the DepositDataRegistry contract
     * @param exitingAssetsClaimDelay The delay after which the assets can be claimed after exiting from staking
     */
    struct EthVaultConstructorArgs {
        address keeper;
        address vaultsRegistry;
        address validatorsRegistry;
        address validatorsWithdrawals;
        address validatorsConsolidations;
        address consolidationsChecker;
        address osTokenVaultController;
        address osTokenConfig;
        address osTokenVaultEscrow;
        address sharedMevEscrow;
        address depositDataRegistry;
        uint64 exitingAssetsClaimDelay;
    }

    /**
     * @dev Struct for initializing the EthVault contract
     * @param capacity The Vault stops accepting deposits after exceeding the capacity
     * @param feePercent The fee percent that is charged by the Vault
     * @param metadataIpfsHash The IPFS hash of the Vault's metadata file
     */
    struct EthVaultInitParams {
        uint256 capacity;
        uint16 feePercent;
        string metadataIpfsHash;
    }

    /**
     * @notice Initializes or upgrades the EthVault contract. Must transfer security deposit during the deployment.
     * @param params The encoded parameters for initializing the EthVault contract
     */
    function initialize(bytes calldata params) external payable;

    /**
     * @notice Deposits assets to the vault and mints OsToken shares to the receiver
     * @param receiver The address to receive the OsToken
     * @param osTokenShares The amount of OsToken shares to mint.
     *        If set to type(uint256).max, max OsToken shares will be minted.
     * @param referrer The address of the referrer
     * @return The amount of OsToken assets minted
     */
    function depositAndMintOsToken(address receiver, uint256 osTokenShares, address referrer)
        external
        payable
        returns (uint256);

    /**
     * @notice Updates the state, deposits assets to the vault and mints OsToken shares to the receiver
     * @param receiver The address to receive the OsToken
     * @param osTokenShares The amount of OsToken shares to mint.
     *        If set to type(uint256).max, max OsToken shares will be minted.
     * @param referrer The address of the referrer
     * @param harvestParams The parameters for the harvest
     * @return The amount of OsToken assets minted
     */
    function updateStateAndDepositAndMintOsToken(
        address receiver,
        uint256 osTokenShares,
        address referrer,
        IKeeperRewards.HarvestParams calldata harvestParams
    ) external payable returns (uint256);
}



// ============================================================
// FILE: src/interfaces/IStrategy.sol
// ============================================================
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity ^0.8.26;

/**
 * @title IStrategy
 * @author StakeWise
 * @notice Defines the interface for the Strategy contract
 */
interface IStrategy {
    /**
     * @notice Strategy Unique Identifier
     * @return The unique identifier of the strategy
     */
    function strategyId() external pure returns (bytes32);
}



// ============================================================
// FILE: src/interfaces/IStrategyProxy.sol
// ============================================================
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity ^0.8.26;

/**
 * @title IStrategyProxy
 * @author StakeWise
 * @notice Defines the interface for the StrategyProxy contract
 */
interface IStrategyProxy {
    /**
     * @notice Initializes the proxy.
     * @param initialOwner The address of the owner
     */
    function initialize(
        address initialOwner
    ) external;

    /**
     * @notice Executes a call on the target contract. Can only be called by the owner.
     * @param target The address of the target contract
     * @param data The call data
     * @return The call result
     */
    function execute(address target, bytes memory data) external payable returns (bytes memory);

    /**
     * @notice Executes a call on the target contract with a native assets transfer. Can only be called by the owner.
     * @param target The address of the target contract
     * @param data The call data
     * @param value The amount of native assets to send
     * @return The call result
     */
    function executeWithValue(address target, bytes memory data, uint256 value) external returns (bytes memory);

    /**
     * @notice Function for sending native assets to the recipient. Can only be called by the owner.
     * @param recipient The address of the recipient
     * @param amount The amount of native assets to send
     */
    function sendValue(address payable recipient, uint256 amount) external;
}



// ============================================================
// FILE: src/leverage/LeverageStrategy.sol
// ============================================================
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity ^0.8.26;

import {IERC20Permit} from '@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import {Math} from '@openzeppelin/contracts/utils/math/Math.sol';
import {Clones} from '@openzeppelin/contracts/proxy/Clones.sol';
import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';
import {Multicall} from '@stakewise-core/base/Multicall.sol';
import {Errors} from '@stakewise-core/libraries/Errors.sol';
import {IKeeperRewards} from '@stakewise-core/interfaces/IKeeperRewards.sol';
import {IVaultOsToken} from '@stakewise-core/interfaces/IVaultOsToken.sol';
import {IVaultState} from '@stakewise-core/interfaces/IVaultState.sol';
import {IOsTokenVaultEscrow} from '@stakewise-core/interfaces/IOsTokenVaultEscrow.sol';
import {IOsTokenVaultController} from '@stakewise-core/interfaces/IOsTokenVaultController.sol';
import {IOsTokenConfig} from '@stakewise-core/interfaces/IOsTokenConfig.sol';
import {IOsTokenFlashLoans} from '@stakewise-core/interfaces/IOsTokenFlashLoans.sol';
import {IOsTokenFlashLoanRecipient} from '@stakewise-core/interfaces/IOsTokenFlashLoanRecipient.sol';
import {IVaultVersion} from '@stakewise-core/interfaces/IVaultVersion.sol';
import {IBalancerVault} from './interfaces/IBalancerVault.sol';
import {ILeverageStrategy} from './interfaces/ILeverageStrategy.sol';
import {IStrategiesRegistry} from '../interfaces/IStrategiesRegistry.sol';
import {IStrategyProxy} from '../interfaces/IStrategyProxy.sol';
import {IStrategy} from '../interfaces/IStrategy.sol';

/**
 * @title LeverageStrategy
 * @author StakeWise
 * @notice Defines the functionality for the leverage strategy
 */
abstract contract LeverageStrategy is Multicall, ILeverageStrategy {
    uint256 private constant _wad = 1e18;
    uint256 private constant _vaultDisabledLiqThreshold = type(uint64).max;
    string internal constant _maxVaultLtvPercentConfigName = 'maxVaultLtvPercent';
    string internal constant _maxBorrowLtvPercentConfigName = 'maxBorrowLtvPercent';
    string internal constant _vaultForceExitLtvPercentConfigName = 'vaultForceExitLtvPercent';
    string internal constant _borrowForceExitLtvPercentConfigName = 'borrowForceExitLtvPercent';
    string internal constant _rescueVaultConfigName = 'rescueVault';
    string internal constant _balancerPoolIdConfigName = 'balancerPoolId';
    string internal constant _strategyUpgradeConfigName = 'upgradeV2';

    // Strategy
    IStrategiesRegistry internal immutable _strategiesRegistry;
    address private immutable _strategyProxyImplementation;

    // OsToken
    IOsTokenVaultController internal immutable _osTokenVaultController;
    IOsTokenConfig internal immutable _osTokenConfig;
    IOsTokenFlashLoans private immutable _osTokenFlashLoans;
    IOsTokenVaultEscrow internal immutable _osTokenVaultEscrow;

    // Balancer
    IBalancerVault private immutable _balancerVault;

    // Tokens
    IERC20 internal immutable _osToken;
    IERC20 internal immutable _assetToken;

    mapping(address proxy => bool isExiting) public isStrategyProxyExiting;

    /**
     * @dev Constructor
     * @param osToken The address of the OsToken contract
     * @param assetToken The address of the asset token contract (e.g. WETH)
     * @param osTokenVaultController The address of the OsTokenVaultController contract
     * @param osTokenConfig The address of the OsTokenConfig contract
     * @param osTokenFlashLoans The address of the OsTokenFlashLoans contract
     * @param osTokenVaultEscrow The address of the OsTokenVaultEscrow contract
     * @param strategiesRegistry The address of the StrategiesRegistry contract
     * @param strategyProxyImplementation The address of the StrategyProxy implementation
     * @param balancerVault The address of the BalancerVault contract
     */
    constructor(
        address osToken,
        address assetToken,
        address osTokenVaultController,
        address osTokenConfig,
        address osTokenFlashLoans,
        address osTokenVaultEscrow,
        address strategiesRegistry,
        address strategyProxyImplementation,
        address balancerVault
    ) {
        _osToken = IERC20(osToken);
        _assetToken = IERC20(assetToken);
        _osTokenVaultController = IOsTokenVaultController(osTokenVaultController);
        _osTokenConfig = IOsTokenConfig(osTokenConfig);
        _osTokenFlashLoans = IOsTokenFlashLoans(osTokenFlashLoans);
        _osTokenVaultEscrow = IOsTokenVaultEscrow(osTokenVaultEscrow);
        _strategiesRegistry = IStrategiesRegistry(strategiesRegistry);
        _strategyProxyImplementation = strategyProxyImplementation;
        _balancerVault = IBalancerVault(balancerVault);
    }

    /// @inheritdoc ILeverageStrategy
    function getStrategyProxy(address vault, address user) public view returns (address proxy) {
        // check whether strategy proxy exists
        bytes32 strategyProxyId = keccak256(abi.encode(strategyId(), vault, user));
        proxy = _strategiesRegistry.strategyProxyIdToProxy(strategyProxyId);
        if (proxy == address(0)) {
            // calculate the proxy address
            return Clones.predictDeterministicAddress(_strategyProxyImplementation, strategyProxyId);
        }
    }

    /// @inheritdoc ILeverageStrategy
    function updateVaultState(address vault, IKeeperRewards.HarvestParams calldata harvestParams) external {
        IVaultState(vault).updateState(harvestParams);
    }

    /// @inheritdoc ILeverageStrategy
    function permit(address vault, uint256 osTokenShares, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        (address proxy,) = _getOrCreateStrategyProxy(vault, msg.sender);
        try IStrategyProxy(proxy).execute(
            address(_osToken),
            abi.encodeWithSelector(
                IERC20Permit(address(_osToken)).permit.selector, msg.sender, proxy, osTokenShares, deadline, v, r, s
            )
        ) {} catch {}
    }

    /// @inheritdoc ILeverageStrategy
    function getFlashloanOsTokenShares(address vault, uint256 osTokenShares) public view returns (uint256) {
        // fetch deposit and borrow LTVs
        uint256 vaultLtv = getVaultLtv(vault);
        uint256 borrowLtv = getBorrowLtv();

        // calculate the amount of osToken shares that can be leveraged
        uint256 totalLtv = Math.mulDiv(vaultLtv, borrowLtv, _wad);
        return Math.mulDiv(osTokenShares, _wad, _wad - totalLtv) - osTokenShares;
    }

    /// @inheritdoc ILeverageStrategy
    function getVaultLtv(
        address vault
    ) public view returns (uint256) {
        uint256 vaultLtvPercent = _osTokenConfig.getConfig(vault).ltvPercent;
        // check whether there is max vault LTV percent set in the strategy config
        bytes memory vaultMaxLtvPercentConfig =
            _strategiesRegistry.getStrategyConfig(strategyId(), _maxVaultLtvPercentConfigName);
        if (vaultMaxLtvPercentConfig.length == 0) {
            return vaultLtvPercent;
        }
        return Math.min(vaultLtvPercent, abi.decode(vaultMaxLtvPercentConfig, (uint256)));
    }

    /// @inheritdoc ILeverageStrategy
    function getVaultState(
        address vault,
        address proxy
    ) public view returns (uint256 stakedAssets, uint256 mintedOsTokenShares) {
        // check harvested
        if (IVaultState(vault).isStateUpdateRequired()) {
            revert Errors.NotHarvested();
        }

        // fetch staked assets
        uint256 stakedShares = IVaultState(vault).getShares(proxy);
        if (stakedShares != 0) {
            stakedAssets = IVaultState(vault).convertToAssets(stakedShares);
        }

        // fetch minted osToken shares
        mintedOsTokenShares = IVaultOsToken(vault).osTokenPositions(proxy);
    }

    /// @inheritdoc ILeverageStrategy
    function canForceEnterExitQueue(address vault, address user) public view returns (bool) {
        address proxy = getStrategyProxy(vault, user);
        bytes32 _strategyId = strategyId();

        // check whether force exit vault LTV is set in the strategy config
        bytes memory vaultForceExitLtvPercentConfig =
            _strategiesRegistry.getStrategyConfig(_strategyId, _vaultForceExitLtvPercentConfigName);
        if (
            vaultForceExitLtvPercentConfig.length != 0
                && _osTokenConfig.getConfig(vault).liqThresholdPercent != _vaultDisabledLiqThreshold
        ) {
            (uint256 stakedAssets, uint256 mintedOsTokenShares) = getVaultState(vault, proxy);
            uint256 mintedOsTokenAssets = _osTokenVaultController.convertToAssets(mintedOsTokenShares);
            uint256 vaultForceExitLtvPercent = abi.decode(vaultForceExitLtvPercentConfig, (uint256));
            // check whether approaching vault liquidation
            if (Math.mulDiv(stakedAssets, vaultForceExitLtvPercent, _wad) <= mintedOsTokenAssets) {
                return true;
            }
        }

        // check whether force exit borrow LTV is set in the strategy config
        bytes memory borrowForceExitLtvPercentConfig =
            _strategiesRegistry.getStrategyConfig(_strategyId, _borrowForceExitLtvPercentConfigName);
        if (borrowForceExitLtvPercentConfig.length != 0) {
            (uint256 borrowedAssets, uint256 suppliedOsTokenShares) = getBorrowState(proxy);
            uint256 suppliedOsTokenAssets = _osTokenVaultController.convertToAssets(suppliedOsTokenShares);
            uint256 borrowForceExitLtvPercent = abi.decode(borrowForceExitLtvPercentConfig, (uint256));
            // check whether approaching borrow liquidation
            if (Math.mulDiv(suppliedOsTokenAssets, borrowForceExitLtvPercent, _wad) <= borrowedAssets) {
                return true;
            }
        }
        return false;
    }

    /// @inheritdoc ILeverageStrategy
    function deposit(address vault, uint256 osTokenShares, address referrer) external {
        if (osTokenShares == 0) revert Errors.InvalidShares();

        // fetch strategy proxy
        (address proxy,) = _getOrCreateStrategyProxy(vault, msg.sender);
        if (isStrategyProxyExiting[proxy]) revert Errors.ExitRequestNotProcessed();

        // transfer osToken shares from user to the proxy
        IStrategyProxy(proxy).execute(
            address(_osToken), abi.encodeWithSelector(_osToken.transferFrom.selector, msg.sender, proxy, osTokenShares)
        );

        // fetch vault state and lending protocol state
        (uint256 stakedAssets, uint256 mintedOsTokenShares) = getVaultState(vault, proxy);
        (uint256 borrowedAssets, uint256 suppliedOsTokenShares) = getBorrowState(proxy);

        // check whether any of the positions exist
        uint256 leverageOsTokenShares = osTokenShares;
        if (stakedAssets != 0 || mintedOsTokenShares != 0 || borrowedAssets != 0 || suppliedOsTokenShares != 0) {
            // supply osToken shares to the lending protocol
            _supplyOsTokenShares(proxy, osTokenShares);
            suppliedOsTokenShares += osTokenShares;

            // borrow max amount of assets from the lending protocol
            uint256 maxBorrowAssets =
                Math.mulDiv(_osTokenVaultController.convertToAssets(suppliedOsTokenShares), getBorrowLtv(), _wad);
            if (borrowedAssets >= maxBorrowAssets) {
                // nothing to borrow
                emit Deposited(vault, msg.sender, osTokenShares, 0, referrer);
                return;
            }
            uint256 assetsToBorrow;
            unchecked {
                // cannot underflow because maxBorrowAssets > borrowedAssets
                assetsToBorrow = maxBorrowAssets - borrowedAssets;
            }
            _borrowAssets(proxy, assetsToBorrow);

            // mint max possible osToken shares
            leverageOsTokenShares = _mintOsTokenShares(vault, proxy, assetsToBorrow, type(uint256).max);
        }

        // calculate flash loaned osToken shares
        uint256 flashloanOsTokenShares = getFlashloanOsTokenShares(vault, leverageOsTokenShares);
        if (flashloanOsTokenShares == 0) {
            // no osToken shares to leverage
            emit Deposited(vault, msg.sender, osTokenShares, 0, referrer);
            return;
        }

        // execute flashloan
        _osTokenFlashLoans.flashLoan(flashloanOsTokenShares, abi.encode(FlashloanAction.Deposit, vault, proxy));

        // emit event
        emit Deposited(vault, msg.sender, osTokenShares, flashloanOsTokenShares, referrer);
    }

    /// @inheritdoc ILeverageStrategy
    function enterExitQueue(address vault, uint256 positionPercent) external returns (uint256 positionTicket) {
        return _enterExitQueue(vault, msg.sender, positionPercent);
    }

    /// @inheritdoc ILeverageStrategy
    function forceEnterExitQueue(address vault, address user) external returns (uint256 positionTicket) {
        if (!canForceEnterExitQueue(vault, user)) revert Errors.AccessDenied();
        return _enterExitQueue(vault, user, _wad);
    }

    function claimExitedAssets(address vault, address user, ExitPosition calldata exitPosition) external {
        // fetch strategy proxy
        address proxy = getStrategyProxy(vault, user);
        if (!isStrategyProxyExiting[proxy]) revert ExitQueueNotEntered();

        // fetch exit position
        (address owner, uint256 exitedAssets, uint256 exitedOsTokenShares) =
            _osTokenVaultEscrow.getPosition(vault, exitPosition.positionTicket);
        if (owner != proxy) revert InvalidExitQueueTicket();

        if (exitedOsTokenShares <= 1) {
            // osToken vault escrow position was redeemed or liquidated
            delete isStrategyProxyExiting[proxy];
            emit ExitedAssetsClaimed(vault, user, 0, 0);
            return;
        }

        if (exitedAssets == 0) {
            // the exit assets are not processed
            _osTokenVaultEscrow.processExitedAssets(
                vault, exitPosition.positionTicket, exitPosition.timestamp, exitPosition.exitQueueIndex
            );
        }

        // flashloan the exited osToken shares
        _osTokenFlashLoans.flashLoan(
            exitedOsTokenShares,
            abi.encode(FlashloanAction.ClaimExitedAssets, vault, proxy, exitPosition.positionTicket)
        );

        // withdraw left assets to the user
        (uint256 claimedOsTokenShares, uint256 claimedAssets) = _claimProxyAssets(proxy, user);

        // update state
        delete isStrategyProxyExiting[proxy];

        // emit event
        emit ExitedAssetsClaimed(vault, user, claimedOsTokenShares, claimedAssets);
    }

    /// @inheritdoc ILeverageStrategy
    function rescueVaultAssets(address vault, ExitPosition calldata exitPosition) external {
        address proxy = getStrategyProxy(vault, msg.sender);
        if (!isStrategyProxyExiting[proxy]) revert ExitQueueNotEntered();

        // fetch exit position
        (address owner, uint256 exitedAssets, uint256 exitedOsTokenShares) =
            _osTokenVaultEscrow.getPosition(vault, exitPosition.positionTicket);
        if (owner != proxy) revert InvalidExitQueueTicket();

        if (exitedOsTokenShares <= 1) {
            // osToken vault escrow position was redeemed or liquidated
            delete isStrategyProxyExiting[proxy];
            emit VaultAssetsRescued(vault, msg.sender, 0, 0);
            return;
        }

        if (exitedAssets == 0) {
            // the exit assets are not processed
            _osTokenVaultEscrow.processExitedAssets(
                vault, exitPosition.positionTicket, exitPosition.timestamp, exitPosition.exitQueueIndex
            );
        }

        // flashloan the exited osToken shares
        _osTokenFlashLoans.flashLoan(
            exitedOsTokenShares,
            abi.encode(FlashloanAction.RescueVaultAssets, vault, proxy, exitPosition.positionTicket)
        );

        // update state
        delete isStrategyProxyExiting[proxy];

        // withdraw left assets to the user
        (uint256 claimedOsTokenShares, uint256 claimedAssets) = _claimProxyAssets(proxy, msg.sender);

        // emit event
        emit VaultAssetsRescued(vault, msg.sender, claimedOsTokenShares, claimedAssets);
    }

    /// @inheritdoc ILeverageStrategy
    function rescueLendingAssets(address vault, uint256 assets, uint256 maxSlippagePercent) external {
        if (maxSlippagePercent >= _wad) revert InvalidMaxSlippagePercent();

        // fetch borrowed assets
        address proxy = getStrategyProxy(vault, msg.sender);
        (uint256 borrowedAssets,) = getBorrowState(proxy);
        if (assets == 0 || assets > borrowedAssets) revert Errors.InvalidAssets();

        // calculate osToken shares to flashloan
        uint256 osTokenShares = _osTokenVaultController.convertToShares(assets);
        // apply max slippage percent
        osTokenShares += Math.mulDiv(osTokenShares, maxSlippagePercent, _wad);

        // flashloan the osToken shares
        _osTokenFlashLoans.flashLoan(osTokenShares, abi.encode(FlashloanAction.RescueLendingAssets, proxy, assets));

        // withdraw left assets to the user
        (uint256 claimedOsTokenShares, uint256 claimedAssets) = _claimProxyAssets(proxy, msg.sender);

        // emit event
        emit LendingAssetsRescued(vault, msg.sender, claimedOsTokenShares, claimedAssets);
    }

    /// @inheritdoc IOsTokenFlashLoanRecipient
    function receiveFlashLoan(uint256 osTokenShares, bytes memory userData) external {
        // validate sender
        if (msg.sender != address(_osTokenFlashLoans)) {
            revert Errors.AccessDenied();
        }

        // decode userData action
        (FlashloanAction flashloanType) = abi.decode(userData, (FlashloanAction));
        if (flashloanType == FlashloanAction.Deposit) {
            // process deposit flashloan
            (, address vault, address proxy) = abi.decode(userData, (FlashloanAction, address, address));
            _processDepositFlashloan(vault, proxy, osTokenShares);
        } else if (flashloanType == FlashloanAction.ClaimExitedAssets) {
            // process claim exited assets flashloan
            (, address vault, address proxy, uint256 exitPositionTicket) =
                abi.decode(userData, (FlashloanAction, address, address, uint256));
            _processClaimFlashloan(vault, proxy, exitPositionTicket, osTokenShares);
        } else if (flashloanType == FlashloanAction.RescueVaultAssets) {
            // process vault assets rescue flashloan
            (, address vault, address proxy, uint256 exitPositionTicket) =
                abi.decode(userData, (FlashloanAction, address, address, uint256));
            _processVaultAssetsRescueFlashloan(vault, proxy, exitPositionTicket, osTokenShares);
        } else if (flashloanType == FlashloanAction.RescueLendingAssets) {
            // process lending assets rescue flashloan
            (, address proxy, uint256 assets) = abi.decode(userData, (FlashloanAction, address, uint256));
            _processLendingAssetsRescueFlashloan(proxy, assets, osTokenShares);
        } else {
            revert InvalidFlashloanAction();
        }
    }

    /// @inheritdoc ILeverageStrategy
    function setStrategyProxyExiting(
        address proxy
    ) external {
        if (!_strategiesRegistry.strategies(msg.sender)) {
            revert Errors.AccessDenied();
        }
        if (isStrategyProxyExiting[proxy]) {
            revert Errors.ValueNotChanged();
        }
        isStrategyProxyExiting[proxy] = true;
        emit StrategyProxyExitingUpdated(proxy, true);
    }

    /// @inheritdoc ILeverageStrategy
    function upgradeProxy(
        address vault
    ) external {
        // fetch strategy proxy
        address proxy = getStrategyProxy(vault, msg.sender);
        if (!_strategiesRegistry.strategyProxies(proxy)) revert Errors.AccessDenied();

        // check whether there is a new version for the current strategy
        bytes memory vaultUpgradeConfig =
            _strategiesRegistry.getStrategyConfig(strategyId(), _strategyUpgradeConfigName);
        if (vaultUpgradeConfig.length == 0) {
            revert Errors.UpgradeFailed();
        }

        // decode and check new strategy address
        address newStrategy = abi.decode(vaultUpgradeConfig, (address));
        if (newStrategy == address(0) || newStrategy == address(this)) {
            revert Errors.ValueNotChanged();
        }

        if (isStrategyProxyExiting[proxy]) {
            ILeverageStrategy(newStrategy).setStrategyProxyExiting(proxy);
        }

        // migrate strategy
        Ownable(proxy).transferOwnership(newStrategy);
        emit StrategyProxyUpgraded(vault, msg.sender, newStrategy);
    }

    /**
     * @dev Enters the exit queue for the strategy proxy
     * @param vault The address of the vault
     * @param user The address of the user
     * @param positionPercent The percentage of the position to exit
     * @return positionTicket The exit position ticket
     */
    function _enterExitQueue(
        address vault,
        address user,
        uint256 positionPercent
    ) private returns (uint256 positionTicket) {
        if (positionPercent == 0 || positionPercent > _wad) {
            revert InvalidExitQueuePercent();
        }

        // fetch strategy proxy
        address proxy = getStrategyProxy(vault, user);
        if (isStrategyProxyExiting[proxy]) revert Errors.ExitRequestNotProcessed();

        // calculate the minted OsToken shares to transfer to the escrow
        (, uint256 mintedOsTokenShares) = getVaultState(vault, proxy);
        uint256 osTokenShares = Math.mulDiv(mintedOsTokenShares, positionPercent, _wad);
        if (osTokenShares == 0) revert Errors.InvalidPosition();

        // initiate exit for assets
        bytes memory response = IStrategyProxy(proxy).execute(
            vault, abi.encodeWithSelector(IVaultOsToken(vault).transferOsTokenPositionToEscrow.selector, osTokenShares)
        );
        positionTicket = abi.decode(response, (uint256));

        // update state
        isStrategyProxyExiting[proxy] = true;

        // emit event
        emit ExitQueueEntered(vault, user, positionTicket, block.timestamp, osTokenShares, positionPercent);
    }

    /**
     * @dev Processes the deposit flashloan
     * @param vault The address of the vault
     * @param proxy The address of the strategy proxy
     * @param flashloanOsTokenShares The amount of flashloan osToken shares
     */
    function _processDepositFlashloan(address vault, address proxy, uint256 flashloanOsTokenShares) private {
        // transfer flashloan to proxy
        SafeERC20.safeTransfer(_osToken, proxy, flashloanOsTokenShares);

        // supply all osToken shares to the lending protocol
        _supplyOsTokenShares(proxy, _osToken.balanceOf(proxy));

        // calculate assets to borrow
        uint256 borrowAssets =
            Math.mulDiv(_osTokenVaultController.convertToAssets(flashloanOsTokenShares), _wad, getVaultLtv(vault));
        borrowAssets += 2; // add 2 wei to avoid rounding errors

        // borrow assets from the lending protocol
        _borrowAssets(proxy, borrowAssets);

        // mint osToken shares
        _mintOsTokenShares(vault, proxy, borrowAssets, flashloanOsTokenShares);

        // transfer flashloan osToken shares to the osTokenFlashLoans contract
        IStrategyProxy(proxy).execute(
            address(_osToken),
            abi.encodeWithSelector(_osToken.transfer.selector, address(_osTokenFlashLoans), flashloanOsTokenShares)
        );
    }

    /**
     * @dev Processes the exited assets claim flashloan
     * @param vault The address of the vault
     * @param proxy The address of the strategy proxy
     * @param exitPositionTicket The exit position ticket
     * @param flashloanOsTokenShares The amount of flashloan osToken shares
     */
    function _processClaimFlashloan(
        address vault,
        address proxy,
        uint256 exitPositionTicket,
        uint256 flashloanOsTokenShares
    ) private {
        // transfer flashloan to proxy
        SafeERC20.safeTransfer(_osToken, proxy, flashloanOsTokenShares);

        // claim exited assets
        uint256 claimedAssets = _claimOsTokenVaultEscrowAssets(vault, proxy, exitPositionTicket, flashloanOsTokenShares);

        // repay borrowed assets
        (uint256 borrowedAssets, uint256 suppliedOsTokenShares) = getBorrowState(proxy);
        uint256 repayAssets = Math.min(borrowedAssets, claimedAssets);
        _repayAssets(proxy, repayAssets);

        unchecked {
            // cannot underflow because repayAssets <= borrowedAssets
            borrowedAssets -= repayAssets;
        }

        // deduct reserved osToken shares from the supplied osToken shares
        if (borrowedAssets != 0) {
            suppliedOsTokenShares -=
                _osTokenVaultController.convertToShares(Math.mulDiv(borrowedAssets, _wad, getBorrowLtv()));
        }

        // withdraw osToken shares
        _withdrawOsTokenShares(proxy, suppliedOsTokenShares);

        // transfer flashloan osToken shares to the osTokenFlashLoans contract
        IStrategyProxy(proxy).execute(
            address(_osToken),
            abi.encodeWithSelector(_osToken.transfer.selector, address(_osTokenFlashLoans), flashloanOsTokenShares)
        );
    }

    /**
     * @dev Processes the vault assets rescue flashloan
     * @param vault The address of the vault
     * @param proxy The address of the strategy proxy
     * @param exitPositionTicket The exit position ticket
     * @param flashloanOsTokenShares The amount of flashloan osToken shares
     */
    function _processVaultAssetsRescueFlashloan(
        address vault,
        address proxy,
        uint256 exitPositionTicket,
        uint256 flashloanOsTokenShares
    ) private {
        // transfer flashloan to proxy
        SafeERC20.safeTransfer(_osToken, proxy, flashloanOsTokenShares);

        // claim exited assets
        uint256 claimedAssets = _claimOsTokenVaultEscrowAssets(vault, proxy, exitPositionTicket, flashloanOsTokenShares);

        // fetch vault with higher LTV than user's vault and proxy addresses
        bytes memory rescueVaultConfig = _strategiesRegistry.getStrategyConfig(strategyId(), _rescueVaultConfigName);
        if (rescueVaultConfig.length == 0) revert Errors.InvalidVault();
        address rescueVault = abi.decode(rescueVaultConfig, (address));
        (address rescueProxy,) = _getOrCreateStrategyProxy(rescueVault, address(1));

        // mint osToken shares to rescue proxy
        IStrategyProxy(proxy).execute(
            address(_assetToken), abi.encodeWithSelector(_assetToken.transfer.selector, rescueProxy, claimedAssets)
        );
        uint256 totalOsTokenShares = _mintOsTokenShares(rescueVault, rescueProxy, claimedAssets, type(uint256).max);

        // transfer flashloan osToken shares to the osTokenFlashLoans contract
        IStrategyProxy(rescueProxy).execute(
            address(_osToken),
            abi.encodeWithSelector(_osToken.transfer.selector, address(_osTokenFlashLoans), flashloanOsTokenShares)
        );

        // transfer left osToken shares to user's proxy
        IStrategyProxy(rescueProxy).execute(
            address(_osToken),
            abi.encodeWithSelector(_osToken.transfer.selector, proxy, totalOsTokenShares - flashloanOsTokenShares)
        );
    }

    /**
     * @dev Processes the lending assets rescue flashloan
     * @param proxy The address of the strategy proxy
     * @param repayAssets The amount of borrowed assets to repay
     * @param flashloanOsTokenShares The amount of flashloan osToken shares
     */
    function _processLendingAssetsRescueFlashloan(
        address proxy,
        uint256 repayAssets,
        uint256 flashloanOsTokenShares
    ) private {
        // transfer flashloan to proxy
        SafeERC20.safeTransfer(_osToken, proxy, flashloanOsTokenShares);

        // fetch Balancer pool ID to execute swap
        bytes memory balancerPoolIdConfig =
            _strategiesRegistry.getStrategyConfig(strategyId(), _balancerPoolIdConfigName);
        if (balancerPoolIdConfig.length == 0) revert InvalidBalancerPoolId();
        bytes32 balancerPoolId = abi.decode(balancerPoolIdConfig, (bytes32));

        // define balancer swap
        IBalancerVault.SingleSwap memory singleSwap = IBalancerVault.SingleSwap({
            poolId: balancerPoolId,
            kind: IBalancerVault.SwapKind.GIVEN_OUT,
            assetIn: address(_osToken),
            assetOut: address(_assetToken),
            amount: repayAssets,
            userData: ''
        });

        // define balancer funds
        IBalancerVault.FundManagement memory funds = IBalancerVault.FundManagement({
            sender: proxy,
            fromInternalBalance: false,
            recipient: payable(proxy),
            toInternalBalance: false
        });

        // swap osToken shares to assets
        IStrategyProxy(proxy).execute(
            address(_osToken),
            abi.encodeWithSelector(_osToken.approve.selector, address(_balancerVault), flashloanOsTokenShares)
        );
        IStrategyProxy(proxy).execute(
            address(_balancerVault),
            abi.encodeWithSelector(
                _balancerVault.swap.selector, singleSwap, funds, flashloanOsTokenShares, block.timestamp
            )
        );

        // repay borrowed assets
        _repayAssets(proxy, repayAssets);

        // calculate osToken shares to withdraw
        (uint256 borrowedAssets, uint256 suppliedOsTokenShares) = getBorrowState(proxy);
        if (borrowedAssets != 0) {
            suppliedOsTokenShares -=
                _osTokenVaultController.convertToShares(Math.mulDiv(borrowedAssets, _wad, getBorrowLtv()));
        }

        // withdraw osToken shares
        _withdrawOsTokenShares(proxy, suppliedOsTokenShares);

        // transfer flashloan osToken shares to the osTokenFlashLoans contract
        IStrategyProxy(proxy).execute(
            address(_osToken),
            abi.encodeWithSelector(_osToken.transfer.selector, address(_osTokenFlashLoans), flashloanOsTokenShares)
        );
    }

    /**
     * @dev Returns the strategy proxy or creates a new one
     * @param vault The address of the vault
     * @param user The address of the user
     * @return proxy The address of the strategy proxy
     * @return isCreated Whether the proxy was created
     */
    function _getOrCreateStrategyProxy(
        address vault,
        address user
    ) internal virtual returns (address proxy, bool isCreated) {
        proxy = getStrategyProxy(vault, user);
        if (_strategiesRegistry.strategyProxies(proxy)) {
            // already registered
            return (proxy, false);
        }

        // check vault and user addresses
        if (user == address(0)) revert Errors.ZeroAddress();
        if (vault == address(0) || IVaultVersion(vault).version() < 3) {
            revert Errors.InvalidVault();
        }

        // create proxy
        bytes32 strategyProxyId = keccak256(abi.encode(strategyId(), vault, user));
        proxy = Clones.cloneDeterministic(_strategyProxyImplementation, strategyProxyId);
        isCreated = true;
        IStrategyProxy(proxy).initialize(address(this));
        _strategiesRegistry.addStrategyProxy(strategyProxyId, proxy);
        emit StrategyProxyCreated(strategyProxyId, vault, user, proxy);
    }

    /**
     * @dev Claims the exited assets from the OsToken vault escrow
     * @param vault The address of the vault
     * @param proxy The address of the strategy proxy
     * @param positionTicket The exit position ticket
     * @param osTokenShares The amount of osToken shares to claim
     * @return claimedAssets The amount of claimed assets
     */
    function _claimOsTokenVaultEscrowAssets(
        address vault,
        address proxy,
        uint256 positionTicket,
        uint256 osTokenShares
    ) internal virtual returns (uint256 claimedAssets) {
        bytes memory response = IStrategyProxy(proxy).execute(
            address(_osTokenVaultEscrow),
            abi.encodeWithSelector(IOsTokenVaultEscrow.claimExitedAssets.selector, vault, positionTicket, osTokenShares)
        );
        return abi.decode(response, (uint256));
    }

    /**
     * @dev Claims assets and osToken shares from the proxy to the user
     * @param proxy The address of the strategy proxy
     * @param user The address of the user that receives the assets
     * @return claimedOsTokenShares The amount of claimed osToken shares
     * @return claimedAssets The amount of claimed assets
     */
    function _claimProxyAssets(
        address proxy,
        address user
    ) private returns (uint256 claimedOsTokenShares, uint256 claimedAssets) {
        // withdraw left osToken shares to the user
        claimedOsTokenShares = _osToken.balanceOf(proxy);
        if (claimedOsTokenShares > 0) {
            IStrategyProxy(proxy).execute(
                address(_osToken), abi.encodeWithSelector(_osToken.transfer.selector, user, claimedOsTokenShares)
            );
        }

        // withdraw left assets to the user
        claimedAssets = _assetToken.balanceOf(proxy);
        if (claimedAssets > 0) {
            _transferAssets(proxy, user, claimedAssets);
        }
    }

    /// @inheritdoc IStrategy
    function strategyId() public pure virtual returns (bytes32);

    /// @inheritdoc ILeverageStrategy
    function getBorrowLtv() public view virtual returns (uint256);

    /// @inheritdoc ILeverageStrategy
    function getBorrowState(
        address proxy
    ) public view virtual returns (uint256 borrowedAssets, uint256 suppliedOsTokenShares);

    /**
     * @dev Deposits assets to the vault and mints osToken shares
     * @param vault The address of the vault
     * @param proxy The address of the strategy proxy
     * @param depositAssets The amount of assets to deposit
     * @param mintOsTokenShares The amount of osToken shares to mint
     * @return The amount of osToken shares minted
     */
    function _mintOsTokenShares(
        address vault,
        address proxy,
        uint256 depositAssets,
        uint256 mintOsTokenShares
    ) internal virtual returns (uint256);

    /**
     * @dev Locks OsToken shares to the lending protocol
     * @param proxy The address of the strategy proxy
     * @param osTokenShares The amount of OsToken shares to lock
     */
    function _supplyOsTokenShares(address proxy, uint256 osTokenShares) internal virtual;

    /**
     * @dev Withdraws OsToken shares from the lending protocol
     * @param proxy The address of the strategy proxy
     * @param osTokenShares The amount of OsToken shares to withdraw
     */
    function _withdrawOsTokenShares(address proxy, uint256 osTokenShares) internal virtual;

    /**
     * @dev Borrows the assets from the lending protocol
     * @param proxy The address of the strategy proxy
     * @param amount The amount of assets borrowed
     */
    function _borrowAssets(address proxy, uint256 amount) internal virtual;

    /**
     * @dev Repays the assets from the lending protocol
     * @param proxy The address of the strategy proxy
     * @param amount The amount of assets to repay
     */
    function _repayAssets(address proxy, uint256 amount) internal virtual;

    /**
     * @dev Transfers assets from the proxy to the receiver
     * @param proxy The address of the strategy proxy
     * @param receiver The address of the receiver
     * @param amount The amount of assets to transfer
     */
    function _transferAssets(address proxy, address receiver, uint256 amount) internal virtual;
}



// ============================================================
// FILE: src/leverage/AaveLeverageStrategy.sol
// ============================================================
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity ^0.8.26;

import {Math} from '@openzeppelin/contracts/utils/math/Math.sol';
import {IPool} from '@aave-core/interfaces/IPool.sol';
import {IScaledBalanceToken} from '@aave-core/interfaces/IScaledBalanceToken.sol';
import {TokenMath} from '@aave-core/protocol/libraries/helpers/TokenMath.sol';
import {IStrategyProxy} from '../interfaces/IStrategyProxy.sol';
import {LeverageStrategy, ILeverageStrategy} from './LeverageStrategy.sol';

/**
 * @title AaveLeverageStrategy
 * @author StakeWise
 * @notice Defines the Aave leverage strategy functionality
 */
abstract contract AaveLeverageStrategy is LeverageStrategy {
    uint8 private constant _emodeCategory = 1;

    IPool private immutable _aavePool;
    IScaledBalanceToken private immutable _aaveOsToken;
    IScaledBalanceToken private immutable _aaveVarDebtAssetToken;

    /**
     * @dev Constructor
     * @param osToken The address of the OsToken contract
     * @param assetToken The address of the asset token contract (e.g. WETH)
     * @param osTokenVaultController The address of the OsTokenVaultController contract
     * @param osTokenConfig The address of the OsTokenConfig contract
     * @param osTokenFlashLoans The address of the OsTokenFlashLoans contract
     * @param osTokenVaultEscrow The address of the OsTokenVaultEscrow contract
     * @param strategiesRegistry The address of the StrategiesRegistry contract
     * @param strategyProxyImplementation The address of the StrategyProxy implementation
     * @param balancerVault The address of the BalancerVault contract
     * @param aavePool The address of the Aave pool contract
     * @param aaveOsToken The address of the Aave OsToken contract
     * @param aaveVarDebtAssetToken The address of the Aave variable debt asset token contract
     */
    constructor(
        address osToken,
        address assetToken,
        address osTokenVaultController,
        address osTokenConfig,
        address osTokenFlashLoans,
        address osTokenVaultEscrow,
        address strategiesRegistry,
        address strategyProxyImplementation,
        address balancerVault,
        address aavePool,
        address aaveOsToken,
        address aaveVarDebtAssetToken
    )
        LeverageStrategy(
            osToken,
            assetToken,
            osTokenVaultController,
            osTokenConfig,
            osTokenFlashLoans,
            osTokenVaultEscrow,
            strategiesRegistry,
            strategyProxyImplementation,
            balancerVault
        )
    {
        _aavePool = IPool(aavePool);
        _aaveOsToken = IScaledBalanceToken(aaveOsToken);
        _aaveVarDebtAssetToken = IScaledBalanceToken(aaveVarDebtAssetToken);
    }

    /// @inheritdoc ILeverageStrategy
    function getBorrowLtv() public view override returns (uint256) {
        // convert to 1e18 precision
        uint256 aaveLtv = uint256(_aavePool.getEModeCategoryCollateralConfig(_emodeCategory).ltv) * 1e14;

        // check whether there is max borrow LTV percent set in the strategy config
        bytes memory maxBorrowLtvPercentConfig =
            _strategiesRegistry.getStrategyConfig(strategyId(), _maxBorrowLtvPercentConfigName);
        if (maxBorrowLtvPercentConfig.length == 0) {
            return aaveLtv;
        }
        return Math.min(aaveLtv, abi.decode(maxBorrowLtvPercentConfig, (uint256)));
    }

    /// @inheritdoc ILeverageStrategy
    function getBorrowState(
        address proxy
    ) public view override returns (uint256 borrowedAssets, uint256 suppliedOsTokenShares) {
        suppliedOsTokenShares = _aaveOsToken.scaledBalanceOf(proxy);
        if (suppliedOsTokenShares != 0) {
            uint256 normalizedIncome = _aavePool.getReserveNormalizedIncome(address(_osToken));
            suppliedOsTokenShares = TokenMath.getATokenBalance(suppliedOsTokenShares, normalizedIncome);
        }

        borrowedAssets = _aaveVarDebtAssetToken.scaledBalanceOf(proxy);
        if (borrowedAssets != 0) {
            uint256 normalizedDebt = _aavePool.getReserveNormalizedVariableDebt(address(_assetToken));
            borrowedAssets = TokenMath.getVTokenBalance(borrowedAssets, normalizedDebt);
        }
    }

    /// @inheritdoc LeverageStrategy
    function _supplyOsTokenShares(address proxy, uint256 osTokenShares) internal override {
        IStrategyProxy(proxy).execute(
            address(_aavePool),
            abi.encodeWithSelector(_aavePool.supply.selector, address(_osToken), osTokenShares, proxy, 0)
        );
    }

    /// @inheritdoc LeverageStrategy
    function _withdrawOsTokenShares(address proxy, uint256 osTokenShares) internal override {
        IStrategyProxy(proxy).execute(
            address(_aavePool),
            abi.encodeWithSelector(_aavePool.withdraw.selector, address(_osToken), osTokenShares, proxy)
        );
    }

    /// @inheritdoc LeverageStrategy
    function _borrowAssets(address proxy, uint256 amount) internal override {
        IStrategyProxy(proxy).execute(
            address(_aavePool),
            abi.encodeWithSelector(_aavePool.borrow.selector, address(_assetToken), amount, 2, 0, proxy)
        );
    }

    /// @inheritdoc LeverageStrategy
    function _repayAssets(address proxy, uint256 amount) internal override {
        IStrategyProxy(proxy).execute(
            address(_aavePool), abi.encodeWithSelector(_aavePool.repay.selector, address(_assetToken), amount, 2, proxy)
        );
    }

    /// @inheritdoc LeverageStrategy
    function _getOrCreateStrategyProxy(
        address vault,
        address user
    ) internal virtual override returns (address proxy, bool isCreated) {
        (proxy, isCreated) = super._getOrCreateStrategyProxy(vault, user);
        if (!isCreated) {
            return (proxy, isCreated);
        }

        // setup emode category
        IStrategyProxy(proxy).execute(
            address(_aavePool), abi.encodeWithSelector(_aavePool.setUserEMode.selector, _emodeCategory)
        );

        // approve Aave pool to spend OsToken and AssetToken
        IStrategyProxy(proxy).execute(
            address(_osToken), abi.encodeWithSelector(_osToken.approve.selector, address(_aavePool), type(uint256).max)
        );
        IStrategyProxy(proxy).execute(
            address(_assetToken),
            abi.encodeWithSelector(_assetToken.approve.selector, address(_aavePool), type(uint256).max)
        );
    }
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IKeeperRewards.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IKeeperOracles} from "./IKeeperOracles.sol";

/**
 * @title IKeeperRewards
 * @author StakeWise
 * @notice Defines the interface for the Keeper contract rewards
 */
interface IKeeperRewards is IKeeperOracles {
    /**
     * @notice Event emitted on rewards update
     * @param caller The address of the function caller
     * @param rewardsRoot The new rewards merkle tree root
     * @param avgRewardPerSecond The new average reward per second
     * @param updateTimestamp The update timestamp used for rewards calculation
     * @param nonce The nonce used for verifying signatures
     * @param rewardsIpfsHash The new rewards IPFS hash
     */
    event RewardsUpdated(
        address indexed caller,
        bytes32 indexed rewardsRoot,
        uint256 avgRewardPerSecond,
        uint64 updateTimestamp,
        uint64 nonce,
        string rewardsIpfsHash
    );

    /**
     * @notice Event emitted on Vault harvest
     * @param vault The address of the Vault
     * @param rewardsRoot The rewards merkle tree root
     * @param totalAssetsDelta The Vault total assets delta since last sync. Can be negative in case of penalty/slashing.
     * @param unlockedMevDelta The Vault execution reward that can be withdrawn from shared MEV escrow. Only used by shared MEV Vaults.
     */
    event Harvested(
        address indexed vault, bytes32 indexed rewardsRoot, int256 totalAssetsDelta, uint256 unlockedMevDelta
    );

    /**
     * @notice Event emitted on rewards min oracles number update
     * @param oracles The new minimum number of oracles required to update rewards
     */
    event RewardsMinOraclesUpdated(uint256 oracles);

    /**
     * @notice A struct containing the last synced Vault's cumulative reward
     * @param assets The Vault cumulative reward earned since the start. Can be negative in case of penalty/slashing.
     * @param nonce The nonce of the last sync
     */
    struct Reward {
        int192 assets;
        uint64 nonce;
    }

    /**
     * @notice A struct containing the last unlocked Vault's cumulative execution reward that can be withdrawn from shared MEV escrow. Only used by shared MEV Vaults.
     * @param assets The shared MEV Vault's cumulative execution reward that can be withdrawn
     * @param nonce The nonce of the last sync
     */
    struct UnlockedMevReward {
        uint192 assets;
        uint64 nonce;
    }

    /**
     * @notice A struct containing parameters for rewards update
     * @param rewardsRoot The new rewards merkle root
     * @param avgRewardPerSecond The new average reward per second
     * @param updateTimestamp The update timestamp used for rewards calculation
     * @param rewardsIpfsHash The new IPFS hash with all the Vaults' rewards for the new root
     * @param signatures The concatenation of the Oracles' signatures
     */
    struct RewardsUpdateParams {
        bytes32 rewardsRoot;
        uint256 avgRewardPerSecond;
        uint64 updateTimestamp;
        string rewardsIpfsHash;
        bytes signatures;
    }

    /**
     * @notice A struct containing parameters for harvesting rewards. Can only be called by Vault.
     * @param rewardsRoot The rewards merkle root
     * @param reward The Vault cumulative reward earned since the start. Can be negative in case of penalty/slashing.
     * @param unlockedMevReward The Vault cumulative execution reward that can be withdrawn from shared MEV escrow. Only used by shared MEV Vaults.
     * @param proof The proof to verify that Vault's reward is correct
     */
    struct HarvestParams {
        bytes32 rewardsRoot;
        int160 reward;
        uint160 unlockedMevReward;
        bytes32[] proof;
    }

    /**
     * @notice Previous Rewards Root
     * @return The previous merkle tree root of the rewards accumulated by the Vaults
     */
    function prevRewardsRoot() external view returns (bytes32);

    /**
     * @notice Rewards Root
     * @return The latest merkle tree root of the rewards accumulated by the Vaults
     */
    function rewardsRoot() external view returns (bytes32);

    /**
     * @notice Rewards Nonce
     * @return The nonce used for updating rewards merkle tree root
     */
    function rewardsNonce() external view returns (uint64);

    /**
     * @notice The last rewards update
     * @return The timestamp of the last rewards update
     */
    function lastRewardsTimestamp() external view returns (uint64);

    /**
     * @notice The minimum number of oracles required to update rewards
     * @return The minimum number of oracles
     */
    function rewardsMinOracles() external view returns (uint256);

    /**
     * @notice The rewards delay
     * @return The delay in seconds between rewards updates
     */
    function rewardsDelay() external view returns (uint256);

    /**
     * @notice Get last synced Vault cumulative reward
     * @param vault The address of the Vault
     * @return assets The last synced reward assets
     * @return nonce The last synced reward nonce
     */
    function rewards(address vault) external view returns (int192 assets, uint64 nonce);

    /**
     * @notice Get last unlocked shared MEV Vault cumulative reward
     * @param vault The address of the Vault
     * @return assets The last synced reward assets
     * @return nonce The last synced reward nonce
     */
    function unlockedMevRewards(address vault) external view returns (uint192 assets, uint64 nonce);

    /**
     * @notice Checks whether Vault must be harvested
     * @param vault The address of the Vault
     * @return `true` if the Vault requires harvesting, `false` otherwise
     */
    function isHarvestRequired(address vault) external view returns (bool);

    /**
     * @notice Checks whether the Vault can be harvested
     * @param vault The address of the Vault
     * @return `true` if Vault can be harvested, `false` otherwise
     */
    function canHarvest(address vault) external view returns (bool);

    /**
     * @notice Checks whether rewards can be updated
     * @return `true` if rewards can be updated, `false` otherwise
     */
    function canUpdateRewards() external view returns (bool);

    /**
     * @notice Checks whether the Vault has registered validators
     * @param vault The address of the Vault
     * @return `true` if Vault is collateralized, `false` otherwise
     */
    function isCollateralized(address vault) external view returns (bool);

    /**
     * @notice Update rewards data
     * @param params The struct containing rewards update parameters
     */
    function updateRewards(RewardsUpdateParams calldata params) external;

    /**
     * @notice Harvest rewards. Can be called only by Vault.
     * @param params The struct containing rewards harvesting parameters
     * @return totalAssetsDelta The total reward/penalty accumulated by the Vault since the last sync
     * @return unlockedMevDelta The Vault execution reward that can be withdrawn from shared MEV escrow. Only used by shared MEV Vaults.
     * @return harvested `true` when the rewards were harvested, `false` otherwise
     */
    function harvest(HarvestParams calldata params)
        external
        returns (int256 totalAssetsDelta, uint256 unlockedMevDelta, bool harvested);

    /**
     * @notice Set min number of oracles for confirming rewards update. Can only be called by the owner.
     * @param _rewardsMinOracles The new min number of oracles for confirming rewards update
     */
    function setRewardsMinOracles(uint256 _rewardsMinOracles) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultAdmin.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

/**
 * @title IVaultState
 * @author StakeWise
 * @notice Defines the interface for the VaultAdmin contract
 */
interface IVaultAdmin {
    /**
     * @notice Event emitted on metadata ipfs hash update
     * @param caller The address of the function caller
     * @param metadataIpfsHash The new metadata IPFS hash
     */
    event MetadataUpdated(address indexed caller, string metadataIpfsHash);

    /**
     * @notice Event emitted on admin update
     * @param caller The address of the function caller
     * @param newAdmin The new admin address
     */
    event AdminUpdated(address indexed caller, address newAdmin);

    /**
     * @notice The Vault admin
     * @return The address of the Vault admin
     */
    function admin() external view returns (address);

    /**
     * @notice Function for updating the metadata IPFS hash. Can only be called by Vault admin.
     * @param metadataIpfsHash The new metadata IPFS hash
     */
    function setMetadata(string calldata metadataIpfsHash) external;

    /**
     * @notice Function for updating the admin address. Can only be called by Vault current admin.
     * @param newAdmin The new admin address
     */
    function setAdmin(address newAdmin) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultVersion.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";
import {IVaultAdmin} from "./IVaultAdmin.sol";

/**
 * @title IVaultVersion
 * @author StakeWise
 * @notice Defines the interface for VaultVersion contract
 */
interface IVaultVersion is IERC1822Proxiable, IVaultAdmin {
    /**
     * @notice Vault Unique Identifier
     * @return The unique identifier of the Vault
     */
    function vaultId() external pure returns (bytes32);

    /**
     * @notice Version
     * @return The version of the Vault implementation contract
     */
    function version() external pure returns (uint8);

    /**
     * @notice Implementation
     * @return The address of the Vault implementation contract
     */
    function implementation() external view returns (address);
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultFee.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IVaultAdmin} from "./IVaultAdmin.sol";

/**
 * @title IVaultFee
 * @author StakeWise
 * @notice Defines the interface for the VaultFee contract
 */
interface IVaultFee is IVaultAdmin {
    /**
     * @notice Event emitted on fee recipient update
     * @param caller The address of the function caller
     * @param feeRecipient The address of the new fee recipient
     */
    event FeeRecipientUpdated(address indexed caller, address indexed feeRecipient);

    /**
     * @notice Event emitted on fee percent update
     * @param caller The address of the function caller
     * @param feePercent The new fee percent
     */
    event FeePercentUpdated(address indexed caller, uint16 feePercent);

    /**
     * @notice The Vault's fee recipient
     * @return The address of the Vault's fee recipient
     */
    function feeRecipient() external view returns (address);

    /**
     * @notice The Vault's fee percent in BPS
     * @return The fee percent applied by the Vault on the rewards
     */
    function feePercent() external view returns (uint16);

    /**
     * @notice Function for updating the fee recipient address. Can only be called by the admin.
     * @param _feeRecipient The address of the new fee recipient
     */
    function setFeeRecipient(address _feeRecipient) external;

    /**
     * @notice Function for updating the fee percent. Can only be called by the admin.
     * @param _feePercent The new fee percent
     */
    function setFeePercent(uint16 _feePercent) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultState.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IKeeperRewards} from "./IKeeperRewards.sol";
import {IVaultFee} from "./IVaultFee.sol";

/**
 * @title IVaultState
 * @author StakeWise
 * @notice Defines the interface for the VaultState contract
 */
interface IVaultState is IVaultFee {
    /**
     * @notice Event emitted on checkpoint creation
     * @param shares The number of burned shares
     * @param assets The amount of exited assets
     */
    event CheckpointCreated(uint256 shares, uint256 assets);

    /**
     * @notice Event emitted on minting fee recipient shares
     * @param receiver The address of the fee recipient
     * @param shares The number of minted shares
     * @param assets The amount of minted assets
     */
    event FeeSharesMinted(address receiver, uint256 shares, uint256 assets);

    /**
     * @notice Event emitted when exiting assets are penalized (deprecated)
     * @param penalty The total penalty amount
     */
    event ExitingAssetsPenalized(uint256 penalty);

    /**
     * @notice Event emitted when the assets are donated to the Vault
     * @param sender The address of the sender
     * @param assets The amount of donated assets
     */
    event AssetsDonated(address sender, uint256 assets);

    /**
     * @notice Total assets in the Vault
     * @return The total amount of the underlying asset that is "managed" by Vault
     */
    function totalAssets() external view returns (uint256);

    /**
     * @notice Function for retrieving total shares
     * @return The amount of shares in existence
     */
    function totalShares() external view returns (uint256);

    /**
     * @notice The Vault's capacity
     * @return The amount after which the Vault stops accepting deposits
     */
    function capacity() external view returns (uint256);

    /**
     * @notice Total assets available in the Vault. They can be staked or withdrawn.
     * @return The total amount of withdrawable assets
     */
    function withdrawableAssets() external view returns (uint256);

    /**
     * @notice Get exit queue data
     * @return queuedShares The number of shares in the exit queue
     * @return unclaimedAssets The amount of unclaimed assets in the exit queue
     * @return totalExitingTickets The total number of exiting tickets
     * @return totalExitingAssets The total amount of exiting assets
     * @return totalTickets The total number of tickets in the exit queue
     */
    function getExitQueueData()
        external
        view
        returns (
            uint128 queuedShares,
            uint128 unclaimedAssets,
            uint128 totalExitingTickets,
            uint128 totalExitingAssets,
            uint256 totalTickets
        );

    /**
     * @notice Returns the number of shares held by an account
     * @param account The account for which to look up the number of shares it has, i.e. its balance
     * @return The number of shares held by the account
     */
    function getShares(address account) external view returns (uint256);

    /**
     * @notice Converts assets to shares
     * @param assets The amount of assets to convert to shares
     * @return shares The amount of shares that the Vault would exchange for the amount of assets provided
     */
    function convertToShares(uint256 assets) external view returns (uint256 shares);

    /**
     * @notice Converts shares to assets
     * @param shares The amount of shares to convert to assets
     * @return assets The amount of assets that the Vault would exchange for the amount of shares provided
     */
    function convertToAssets(uint256 shares) external view returns (uint256 assets);

    /**
     * @notice Check whether state update is required
     * @return `true` if state update is required, `false` otherwise
     */
    function isStateUpdateRequired() external view returns (bool);

    /**
     * @notice Updates the total amount of assets in the Vault and its exit queue
     * @param harvestParams The parameters for harvesting Keeper rewards
     */
    function updateState(IKeeperRewards.HarvestParams calldata harvestParams) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultValidators.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IKeeperValidators} from "./IKeeperValidators.sol";
import {IVaultAdmin} from "./IVaultAdmin.sol";
import {IVaultState} from "./IVaultState.sol";

/**
 * @title IVaultValidators
 * @author StakeWise
 * @notice Defines the interface for VaultValidators contract
 */
interface IVaultValidators is IVaultAdmin, IVaultState {
    /**
     * @notice Event emitted on V1 validator registration
     * @param publicKey The public key of the validator that was registered
     */
    event ValidatorRegistered(bytes publicKey);

    /**
     * @notice Event emitted on V2 validator registration
     * @param publicKey The public key of the validator that was registered
     * @param amount The amount of assets that was registered
     */
    event V2ValidatorRegistered(bytes publicKey, uint256 amount);

    /**
     * @notice Event emitted on validator withdrawal
     * @param publicKey The public key of the validator that was withdrawn
     * @param amount The amount of assets that was withdrawn
     * @param feePaid The amount of fee that was paid
     */
    event ValidatorWithdrawalSubmitted(bytes publicKey, uint256 amount, uint256 feePaid);

    /**
     * @notice Event emitted on validator balance top-up
     * @param publicKey The public key of the validator that was funded
     * @param amount The amount of assets that was funded
     */
    event ValidatorFunded(bytes publicKey, uint256 amount);

    /**
     * @notice Event emitted on validators consolidation
     * @param fromPublicKey The public key of the validator that was consolidated
     * @param toPublicKey The public key of the validator that was consolidated to
     * @param feePaid The amount of fee that was paid
     */
    event ValidatorConsolidationSubmitted(bytes fromPublicKey, bytes toPublicKey, uint256 feePaid);

    /**
     * @notice Event emitted on keys manager address update (deprecated)
     * @param caller The address of the function caller
     * @param keysManager The address of the new keys manager
     */
    event KeysManagerUpdated(address indexed caller, address indexed keysManager);

    /**
     * @notice Event emitted on validators merkle tree root update (deprecated)
     * @param caller The address of the function caller
     * @param validatorsRoot The new validators merkle tree root
     */
    event ValidatorsRootUpdated(address indexed caller, bytes32 indexed validatorsRoot);

    /**
     * @notice Event emitted on validators manager address update
     * @param caller The address of the function caller
     * @param validatorsManager The address of the new validators manager
     */
    event ValidatorsManagerUpdated(address indexed caller, address indexed validatorsManager);

    /**
     * @notice The Vault validators manager address
     * @return The address that can register validators
     */
    function validatorsManager() external view returns (address);

    /**
     * @notice The nonce for the validators manager used for signing
     * @return The nonce for the validators manager
     */
    function validatorsManagerNonce() external view returns (uint256);

    /**
     * @notice Function for checking if the validator is tracked V2 validator
     * @param publicKeyHash The keccak256 hash of the public key of the validator
     * @return Whether the validator is tracked V2 validator
     */
    function v2Validators(bytes32 publicKeyHash) external view returns (bool);

    /**
     * @notice Function for funding single or multiple existing validators
     * @param validators The concatenated validators data
     * @param validatorsManagerSignature The optional signature from the validators manager
     */
    function fundValidators(bytes calldata validators, bytes calldata validatorsManagerSignature) external;

    /**
     * @notice Function for withdrawing single or multiple validators
     * @param validators The concatenated validators data
     * @param validatorsManagerSignature The optional signature from the validators manager
     */
    function withdrawValidators(bytes calldata validators, bytes calldata validatorsManagerSignature)
        external
        payable;

    /**
     * @notice Function for consolidating single or multiple validators
     * @param validators The concatenated validators data
     * @param validatorsManagerSignature The optional signature from the validators manager
     * @param oracleSignatures The optional signatures from the oracles
     */
    function consolidateValidators(
        bytes calldata validators,
        bytes calldata validatorsManagerSignature,
        bytes calldata oracleSignatures
    ) external payable;

    /**
     * @notice Function for registering single or multiple validators
     * @param keeperParams The parameters for getting approval from Keeper oracles
     * @param validatorsManagerSignature The optional signature from the validators manager
     */
    function registerValidators(
        IKeeperValidators.ApprovalParams calldata keeperParams,
        bytes calldata validatorsManagerSignature
    ) external;

    /**
     * @notice Function for updating the validators manager. Can only be called by the admin. Default is the DepositDataRegistry contract.
     * @param _validatorsManager The new validators manager address
     */
    function setValidatorsManager(address _validatorsManager) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultEnterExit.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IVaultState} from "./IVaultState.sol";

/**
 * @title IVaultEnterExit
 * @author StakeWise
 * @notice Defines the interface for the VaultEnterExit contract
 */
interface IVaultEnterExit is IVaultState {
    /**
     * @notice Event emitted on deposit
     * @param caller The address that called the deposit function
     * @param receiver The address that received the shares
     * @param assets The number of assets deposited by the caller
     * @param shares The number of shares received
     * @param referrer The address of the referrer
     */
    event Deposited(address indexed caller, address indexed receiver, uint256 assets, uint256 shares, address referrer);

    /**
     * @notice Event emitted on redeem
     * @param owner The address that owns the shares
     * @param receiver The address that received withdrawn assets
     * @param assets The total number of withdrawn assets
     * @param shares The total number of withdrawn shares
     */
    event Redeemed(address indexed owner, address indexed receiver, uint256 assets, uint256 shares);

    /**
     * @notice Event emitted on shares added to the exit queue
     * @param owner The address that owns the shares
     * @param receiver The address that will receive withdrawn assets
     * @param positionTicket The exit queue ticket that was assigned to the position
     * @param shares The number of shares that queued for the exit
     */
    event ExitQueueEntered(address indexed owner, address indexed receiver, uint256 positionTicket, uint256 shares);

    /**
     * @notice Event emitted on shares added to the V2 exit queue (deprecated)
     * @param owner The address that owns the shares
     * @param receiver The address that will receive withdrawn assets
     * @param positionTicket The exit queue ticket that was assigned to the position
     * @param shares The number of shares that queued for the exit
     * @param assets The number of assets that queued for the exit
     */
    event V2ExitQueueEntered(
        address indexed owner, address indexed receiver, uint256 positionTicket, uint256 shares, uint256 assets
    );

    /**
     * @notice Event emitted on claim of the exited assets
     * @param receiver The address that has received withdrawn assets
     * @param prevPositionTicket The exit queue ticket received after the `enterExitQueue` call
     * @param newPositionTicket The new exit queue ticket in case not all the shares were withdrawn. Otherwise 0.
     * @param withdrawnAssets The total number of assets withdrawn
     */
    event ExitedAssetsClaimed(
        address indexed receiver, uint256 prevPositionTicket, uint256 newPositionTicket, uint256 withdrawnAssets
    );

    /**
     * @notice Locks shares to the exit queue. The shares continue earning rewards until they will be burned by the Vault.
     * @param shares The number of shares to lock
     * @param receiver The address that will receive assets upon withdrawal
     * @return positionTicket The position ticket of the exit queue. Returns uint256 max if no ticket created.
     */
    function enterExitQueue(uint256 shares, address receiver) external returns (uint256 positionTicket);

    /**
     * @notice Get the exit queue index to claim exited assets from
     * @param positionTicket The exit queue position ticket to get the index for
     * @return The exit queue index that should be used to claim exited assets.
     *         Returns -1 in case such index does not exist.
     */
    function getExitQueueIndex(uint256 positionTicket) external view returns (int256);

    /**
     * @notice Calculates the number of shares and assets that can be claimed from the exit queue.
     * @param receiver The address that will receive assets upon withdrawal
     * @param positionTicket The exit queue ticket received after the `enterExitQueue` call
     * @param timestamp The timestamp when the shares entered the exit queue
     * @param exitQueueIndex The exit queue index at which the shares were burned. It can be looked up by calling `getExitQueueIndex`.
     * @return leftTickets The number of tickets left in the queue
     * @return exitedTickets The number of tickets that have already exited
     * @return exitedAssets The number of assets that can be claimed
     */
    function calculateExitedAssets(address receiver, uint256 positionTicket, uint256 timestamp, uint256 exitQueueIndex)
        external
        view
        returns (uint256 leftTickets, uint256 exitedTickets, uint256 exitedAssets);

    /**
     * @notice Claims assets that were withdrawn by the Vault. It can be called only after the `enterExitQueue` call by the `receiver`.
     * @param positionTicket The exit queue ticket received after the `enterExitQueue` call
     * @param timestamp The timestamp when the assets entered the exit queue
     * @param exitQueueIndex The exit queue index at which the shares were burned.
     *        It can be looked up by calling `getExitQueueIndex`.
     */
    function claimExitedAssets(uint256 positionTicket, uint256 timestamp, uint256 exitQueueIndex) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultOsToken.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IVaultState} from "./IVaultState.sol";
import {IVaultEnterExit} from "./IVaultEnterExit.sol";

/**
 * @title IVaultOsToken
 * @author StakeWise
 * @notice Defines the interface for the VaultOsToken contract
 */
interface IVaultOsToken is IVaultState, IVaultEnterExit {
    /**
     * @notice Event emitted on minting osToken
     * @param caller The address of the function caller
     * @param receiver The address of the osToken receiver
     * @param assets The amount of minted assets
     * @param shares The amount of minted shares
     * @param referrer The address of the referrer
     */
    event OsTokenMinted(address indexed caller, address receiver, uint256 assets, uint256 shares, address referrer);

    /**
     * @notice Event emitted on burning OsToken
     * @param caller The address of the function caller
     * @param assets The amount of burned assets
     * @param shares The amount of burned shares
     */
    event OsTokenBurned(address indexed caller, uint256 assets, uint256 shares);

    /**
     * @notice Event emitted on osToken position liquidation
     * @param caller The address of the function caller
     * @param user The address of the user liquidated
     * @param receiver The address of the receiver of the liquidated assets
     * @param osTokenShares The amount of osToken shares to liquidate
     * @param shares The amount of vault shares burned
     * @param receivedAssets The amount of assets received
     */
    event OsTokenLiquidated(
        address indexed caller,
        address indexed user,
        address receiver,
        uint256 osTokenShares,
        uint256 shares,
        uint256 receivedAssets
    );

    /**
     * @notice Event emitted on osToken position redemption
     * @param caller The address of the function caller
     * @param user The address of the position owner to redeem from
     * @param receiver The address of the receiver of the redeemed assets
     * @param osTokenShares The amount of osToken shares to redeem
     * @param shares The amount of vault shares burned
     * @param assets The amount of assets received
     */
    event OsTokenRedeemed(
        address indexed caller,
        address indexed user,
        address receiver,
        uint256 osTokenShares,
        uint256 shares,
        uint256 assets
    );

    /**
     * @notice Struct of osToken position
     * @param shares The total number of minted osToken shares. Will increase based on the treasury fee.
     * @param cumulativeFeePerShare The cumulative fee per share
     */
    struct OsTokenPosition {
        uint128 shares;
        uint128 cumulativeFeePerShare;
    }

    /**
     * @notice Get total amount of minted osToken shares
     * @param user The address of the user
     * @return shares The number of minted osToken shares
     */
    function osTokenPositions(address user) external view returns (uint128 shares);

    /**
     * @notice Mints OsToken shares
     * @param receiver The address that will receive the minted OsToken shares
     * @param osTokenShares The number of OsToken shares to mint to the receiver. To mint the maximum amount of shares, use 2^256 - 1.
     * @param referrer The address of the referrer
     * @return assets The number of assets minted to the receiver
     */
    function mintOsToken(address receiver, uint256 osTokenShares, address referrer) external returns (uint256 assets);

    /**
     * @notice Burns osToken shares
     * @param osTokenShares The number of shares to burn
     * @return assets The number of assets burned
     */
    function burnOsToken(uint128 osTokenShares) external returns (uint256 assets);

    /**
     * @notice Liquidates a user position and returns the number of received assets.
     *         Can only be called when health factor is below 1 by the liquidator.
     * @param osTokenShares The number of shares to cover
     * @param owner The address of the position owner to liquidate
     * @param receiver The address of the receiver of the liquidated assets
     */
    function liquidateOsToken(uint256 osTokenShares, address owner, address receiver) external;

    /**
     * @notice Redeems osToken shares for assets. Can only be called when health factor is above redeemFromHealthFactor by the redeemer.
     * @param osTokenShares The number of osToken shares to redeem
     * @param owner The address of the position owner to redeem from
     * @param receiver The address of the receiver of the redeemed assets
     */
    function redeemOsToken(uint256 osTokenShares, address owner, address receiver) external;

    /**
     * @notice Transfers minted osToken shares to the OsTokenVaultEscrow contract, enters the exit queue for staked assets
     * @param osTokenShares The number of osToken shares to transfer
     * @return positionTicket The exit position ticket
     */
    function transferOsTokenPositionToEscrow(uint256 osTokenShares) external returns (uint256 positionTicket);
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultMev.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IVaultState} from "./IVaultState.sol";

/**
 * @title IVaultMev
 * @author StakeWise
 * @notice Common interface for the VaultMev contracts
 */
interface IVaultMev is IVaultState {
    /**
     * @notice The contract that accumulates MEV rewards
     * @return The MEV escrow contract address
     */
    function mevEscrow() external view returns (address);
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IVaultEthStaking.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IVaultState} from "./IVaultState.sol";
import {IVaultValidators} from "./IVaultValidators.sol";
import {IVaultEnterExit} from "./IVaultEnterExit.sol";
import {IKeeperRewards} from "./IKeeperRewards.sol";
import {IVaultMev} from "./IVaultMev.sol";

/**
 * @title IVaultEthStaking
 * @author StakeWise
 * @notice Defines the interface for the VaultEthStaking contract
 */
interface IVaultEthStaking is IVaultState, IVaultValidators, IVaultEnterExit, IVaultMev {
    /**
     * @notice Deposit ETH to the Vault
     * @param receiver The address that will receive Vault's shares
     * @param referrer The address of the referrer. Set to zero address if not used.
     * @return shares The number of shares minted
     */
    function deposit(address receiver, address referrer) external payable returns (uint256 shares);

    /**
     * @notice Used by MEV escrow to transfer ETH.
     */
    function receiveFromMevEscrow() external payable;

    /**
     * @notice Donate assets to the Vault. Must transfer ETH together with the call.
     */
    function donateAssets() external payable;

    /**
     * @notice Updates Vault state and deposits ETH to the Vault
     * @param receiver The address that will receive Vault's shares
     * @param referrer The address of the referrer. Set to zero address if not used.
     * @param harvestParams The parameters for harvesting Keeper rewards
     * @return shares The number of shares minted
     */
    function updateStateAndDeposit(
        address receiver,
        address referrer,
        IKeeperRewards.HarvestParams calldata harvestParams
    ) external payable returns (uint256 shares);
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IMulticall.sol
// ============================================================
// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.22;

/**
 * @title Multicall
 * @author Uniswap
 * @notice Adopted from https://github.com/Uniswap/v3-periphery/blob/1d69caf0d6c8cfeae9acd1f34ead30018d6e6400/contracts/base/Multicall.sol
 * @notice Enables calling multiple methods in a single call to the contract
 */
interface IMulticall {
    /**
     * @notice Call multiple functions in the current contract and return the data from all of them if they all succeed
     * @param data The encoded function data for each of the calls to make to this contract
     * @return results The results from each of the calls passed in via data
     */
    function multicall(bytes[] calldata data) external returns (bytes[] memory results);
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (token/ERC20/extensions/IERC20Permit.sol)

pragma solidity >=0.4.16;

/**
 * @dev Interface of the ERC-20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[ERC-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC-20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on {IERC20-approve}, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 *
 * ==== Security Considerations
 *
 * There are two important considerations concerning the use of `permit`. The first is that a valid permit signature
 * expresses an allowance, and it should not be assumed to convey additional meaning. In particular, it should not be
 * considered as an intention to spend the allowance in any specific way. The second is that because permits have
 * built-in replay protection and can be submitted by anyone, they can be frontrun. A protocol that uses permits should
 * take this into consideration and allow a `permit` call to fail. Combining these two aspects, a pattern that may be
 * generally recommended is:
 *
 * ```solidity
 * function doThingWithPermit(..., uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public {
 *     try token.permit(msg.sender, address(this), value, deadline, v, r, s) {} catch {}
 *     doThing(..., value);
 * }
 *
 * function doThing(..., uint256 value) public {
 *     token.safeTransferFrom(msg.sender, address(this), value);
 *     ...
 * }
 * ```
 *
 * Observe that: 1) `msg.sender` is used as the owner, leaving no ambiguity as to the signer intent, and 2) the use of
 * `try/catch` allows the permit to fail and makes the code tolerant to frontrunning. (See also
 * {SafeERC20-safeTransferFrom}).
 *
 * Additionally, note that smart contract wallets (such as Argent or Safe) are not able to produce permit signatures, so
 * contracts should have entry points that don't rely on permit.
 */
interface IERC20Permit {
    /**
     * @dev Sets `value` as the allowance of `spender` over ``owner``'s tokens,
     * given ``owner``'s signed approval.
     *
     * IMPORTANT: The same issues {IERC20-approve} has related to transaction
     * ordering also apply here.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `deadline` must be a timestamp in the future.
     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`
     * over the EIP712-formatted function arguments.
     * - the signature must use ``owner``'s current nonce (see {nonces}).
     *
     * For more information on the signature format, see the
     * https://eips.ethereum.org/EIPS/eip-2612#specification[relevant EIP
     * section].
     *
     * CAUTION: See Security Considerations above.
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @dev Returns the current nonce for `owner`. This value must be
     * included whenever a signature is generated for {permit}.
     *
     * Every successful call to {permit} increases ``owner``'s nonce by one. This
     * prevents a signature from being used multiple times.
     */
    function nonces(address owner) external view returns (uint256);

    /**
     * @dev Returns the domain separator used in the encoding of the signature for {permit}, as defined by {EIP712}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (token/ERC20/IERC20.sol)

pragma solidity >=0.4.16;

/**
 * @dev Interface of the ERC-20 standard as defined in the ERC.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.3.0) (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.20;

import {IERC20} from "../IERC20.sol";
import {IERC1363} from "../../../interfaces/IERC1363.sol";

/**
 * @title SafeERC20
 * @dev Wrappers around ERC-20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    /**
     * @dev An operation with an ERC-20 token failed.
     */
    error SafeERC20FailedOperation(address token);

    /**
     * @dev Indicates a failed `decreaseAllowance` request.
     */
    error SafeERC20FailedDecreaseAllowance(address spender, uint256 currentAllowance, uint256 requestedDecrease);

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Variant of {safeTransfer} that returns a bool instead of reverting if the operation is not successful.
     */
    function trySafeTransfer(IERC20 token, address to, uint256 value) internal returns (bool) {
        return _callOptionalReturnBool(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Variant of {safeTransferFrom} that returns a bool instead of reverting if the operation is not successful.
     */
    function trySafeTransferFrom(IERC20 token, address from, address to, uint256 value) internal returns (bool) {
        return _callOptionalReturnBool(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     *
     * IMPORTANT: If the token implements ERC-7674 (ERC-20 with temporary allowance), and if the "client"
     * smart contract uses ERC-7674 to set temporary allowances, then the "client" smart contract should avoid using
     * this function. Performing a {safeIncreaseAllowance} or {safeDecreaseAllowance} operation on a token contract
     * that has a non-zero temporary allowance (for that particular owner-spender) will result in unexpected behavior.
     */
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `requestedDecrease`. If `token` returns no
     * value, non-reverting calls are assumed to be successful.
     *
     * IMPORTANT: If the token implements ERC-7674 (ERC-20 with temporary allowance), and if the "client"
     * smart contract uses ERC-7674 to set temporary allowances, then the "client" smart contract should avoid using
     * this function. Performing a {safeIncreaseAllowance} or {safeDecreaseAllowance} operation on a token contract
     * that has a non-zero temporary allowance (for that particular owner-spender) will result in unexpected behavior.
     */
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 requestedDecrease) internal {
        unchecked {
            uint256 currentAllowance = token.allowance(address(this), spender);
            if (currentAllowance < requestedDecrease) {
                revert SafeERC20FailedDecreaseAllowance(spender, currentAllowance, requestedDecrease);
            }
            forceApprove(token, spender, currentAllowance - requestedDecrease);
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     *
     * NOTE: If the token implements ERC-7674, this function will not modify any temporary allowance. This function
     * only sets the "standard" allowance. Any temporary allowance will remain active, in addition to the value being
     * set here.
     */
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(token, approvalCall);
        }
    }

    /**
     * @dev Performs an {ERC1363} transferAndCall, with a fallback to the simple {ERC20} transfer if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferAndCallRelaxed(IERC1363 token, address to, uint256 value, bytes memory data) internal {
        if (to.code.length == 0) {
            safeTransfer(token, to, value);
        } else if (!token.transferAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} transferFromAndCall, with a fallback to the simple {ERC20} transferFrom if the target
     * has no code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferFromAndCallRelaxed(
        IERC1363 token,
        address from,
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        if (to.code.length == 0) {
            safeTransferFrom(token, from, to, value);
        } else if (!token.transferFromAndCall(from, to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} approveAndCall, with a fallback to the simple {ERC20} approve if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * NOTE: When the recipient address (`to`) has no code (i.e. is an EOA), this function behaves as {forceApprove}.
     * Opposedly, when the recipient address (`to`) has code, this function only attempts to call {ERC1363-approveAndCall}
     * once without retrying, and relies on the returned value to be true.
     *
     * Reverts if the returned value is other than `true`.
     */
    function approveAndCallRelaxed(IERC1363 token, address to, uint256 value, bytes memory data) internal {
        if (to.code.length == 0) {
            forceApprove(token, to, value);
        } else if (!token.approveAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturnBool} that reverts if call fails to meet the requirements.
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            let success := call(gas(), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            // bubble errors
            if iszero(success) {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
            returnSize := returndatasize()
            returnValue := mload(0)
        }

        if (returnSize == 0 ? address(token).code.length == 0 : returnValue != 1) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturn} that silently catches all reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {
        bool success;
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            success := call(gas(), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            returnSize := returndatasize()
            returnValue := mload(0)
        }
        return success && (returnSize == 0 ? address(token).code.length > 0 : returnValue == 1);
    }
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/utils/math/Math.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.3.0) (utils/math/Math.sol)

pragma solidity ^0.8.20;

import {Panic} from "../Panic.sol";
import {SafeCast} from "./SafeCast.sol";

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Return the 512-bit addition of two uint256.
     *
     * The result is stored in two 256 variables such that sum = high * 2²⁵⁶ + low.
     */
    function add512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        assembly ("memory-safe") {
            low := add(a, b)
            high := lt(low, a)
        }
    }

    /**
     * @dev Return the 512-bit multiplication of two uint256.
     *
     * The result is stored in two 256 variables such that product = high * 2²⁵⁶ + low.
     */
    function mul512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        // 512-bit multiply [high low] = x * y. Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1, then use
        // the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
        // variables such that product = high * 2²⁵⁶ + low.
        assembly ("memory-safe") {
            let mm := mulmod(a, b, not(0))
            low := mul(a, b)
            high := sub(sub(mm, low), lt(mm, low))
        }
    }

    /**
     * @dev Returns the addition of two unsigned integers, with a success flag (no overflow).
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a + b;
            success = c >= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with a success flag (no overflow).
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a - b;
            success = c <= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with a success flag (no overflow).
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a * b;
            assembly ("memory-safe") {
                // Only true when the multiplication doesn't overflow
                // (c / a == b) || (a == 0)
                success := or(eq(div(c, a), b), iszero(a))
            }
            // equivalent to: success ? c : 0
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a success flag (no division by zero).
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `DIV` opcode returns zero when the denominator is 0.
                result := div(a, b)
            }
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a success flag (no division by zero).
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `MOD` opcode returns zero when the denominator is 0.
                result := mod(a, b)
            }
        }
    }

    /**
     * @dev Unsigned saturating addition, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryAdd(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Unsigned saturating subtraction, bounds to zero instead of overflowing.
     */
    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        (, uint256 result) = trySub(a, b);
        return result;
    }

    /**
     * @dev Unsigned saturating multiplication, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingMul(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryMul(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Branchless ternary evaluation for `a ? b : c`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `a ? b : c`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * SafeCast.toUint(condition));
        }
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }

        // The following calculation ensures accurate ceiling division without overflow.
        // Since a is non-zero, (a - 1) / b will not overflow.
        // The largest possible result occurs when (a - 1) / b is type(uint256).max,
        // but the largest value we can obtain is type(uint256).max - 1, which happens
        // when a = type(uint256).max and b = 1.
        unchecked {
            return SafeCast.toUint(a > 0) * ((a - 1) / b + 1);
        }
    }

    /**
     * @dev Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     *
     * Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);

            // Handle non-overflow cases, 256 by 256 division.
            if (high == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return low / denominator;
            }

            // Make sure the result is less than 2²⁵⁶. Also prevents denominator == 0.
            if (denominator <= high) {
                Panic.panic(ternary(denominator == 0, Panic.DIVISION_BY_ZERO, Panic.UNDER_OVERFLOW));
            }

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [high low].
            uint256 remainder;
            assembly ("memory-safe") {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                high := sub(high, gt(remainder, low))
                low := sub(low, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
            assembly ("memory-safe") {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [high low] by twos.
                low := div(low, twos)

                // Flip twos such that it is 2²⁵⁶ / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from high into low.
            low |= high * twos;

            // Invert denominator mod 2²⁵⁶. Now that denominator is an odd number, it has an inverse modulo 2²⁵⁶ such
            // that denominator * inv ≡ 1 mod 2²⁵⁶. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv ≡ 1 mod 2⁴.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2¹⁶
            inverse *= 2 - denominator * inverse; // inverse mod 2³²
            inverse *= 2 - denominator * inverse; // inverse mod 2⁶⁴
            inverse *= 2 - denominator * inverse; // inverse mod 2¹²⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2²⁵⁶

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2²⁵⁶. Since the preconditions guarantee that the outcome is
            // less than 2²⁵⁶, this is the final result. We don't need to compute the high bits of the result and high
            // is no longer required.
            result = low * inverse;
            return result;
        }
    }

    /**
     * @dev Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        return mulDiv(x, y, denominator) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0);
    }

    /**
     * @dev Calculates floor(x * y >> n) with full precision. Throws if result overflows a uint256.
     */
    function mulShr(uint256 x, uint256 y, uint8 n) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);
            if (high >= 1 << n) {
                Panic.panic(Panic.UNDER_OVERFLOW);
            }
            return (high << (256 - n)) | (low >> n);
        }
    }

    /**
     * @dev Calculates x * y >> n with full precision, following the selected rounding direction.
     */
    function mulShr(uint256 x, uint256 y, uint8 n, Rounding rounding) internal pure returns (uint256) {
        return mulShr(x, y, n) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, 1 << n) > 0);
    }

    /**
     * @dev Calculate the modular multiplicative inverse of a number in Z/nZ.
     *
     * If n is a prime, then Z/nZ is a field. In that case all elements are inversible, except 0.
     * If n is not a prime, then Z/nZ is not a field, and some elements might not be inversible.
     *
     * If the input value is not inversible, 0 is returned.
     *
     * NOTE: If you know for sure that n is (big) a prime, it may be cheaper to use Fermat's little theorem and get the
     * inverse using `Math.modExp(a, n - 2, n)`. See {invModPrime}.
     */
    function invMod(uint256 a, uint256 n) internal pure returns (uint256) {
        unchecked {
            if (n == 0) return 0;

            // The inverse modulo is calculated using the Extended Euclidean Algorithm (iterative version)
            // Used to compute integers x and y such that: ax + ny = gcd(a, n).
            // When the gcd is 1, then the inverse of a modulo n exists and it's x.
            // ax + ny = 1
            // ax = 1 + (-y)n
            // ax ≡ 1 (mod n) # x is the inverse of a modulo n

            // If the remainder is 0 the gcd is n right away.
            uint256 remainder = a % n;
            uint256 gcd = n;

            // Therefore the initial coefficients are:
            // ax + ny = gcd(a, n) = n
            // 0a + 1n = n
            int256 x = 0;
            int256 y = 1;

            while (remainder != 0) {
                uint256 quotient = gcd / remainder;

                (gcd, remainder) = (
                    // The old remainder is the next gcd to try.
                    remainder,
                    // Compute the next remainder.
                    // Can't overflow given that (a % gcd) * (gcd // (a % gcd)) <= gcd
                    // where gcd is at most n (capped to type(uint256).max)
                    gcd - remainder * quotient
                );

                (x, y) = (
                    // Increment the coefficient of a.
                    y,
                    // Decrement the coefficient of n.
                    // Can overflow, but the result is casted to uint256 so that the
                    // next value of y is "wrapped around" to a value between 0 and n - 1.
                    x - y * int256(quotient)
                );
            }

            if (gcd != 1) return 0; // No inverse exists.
            return ternary(x < 0, n - uint256(-x), uint256(x)); // Wrap the result if it's negative.
        }
    }

    /**
     * @dev Variant of {invMod}. More efficient, but only works if `p` is known to be a prime greater than `2`.
     *
     * From https://en.wikipedia.org/wiki/Fermat%27s_little_theorem[Fermat's little theorem], we know that if p is
     * prime, then `a**(p-1) ≡ 1 mod p`. As a consequence, we have `a * a**(p-2) ≡ 1 mod p`, which means that
     * `a**(p-2)` is the modular multiplicative inverse of a in Fp.
     *
     * NOTE: this function does NOT check that `p` is a prime greater than `2`.
     */
    function invModPrime(uint256 a, uint256 p) internal view returns (uint256) {
        unchecked {
            return Math.modExp(a, p - 2, p);
        }
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m)
     *
     * Requirements:
     * - modulus can't be zero
     * - underlying staticcall to precompile must succeed
     *
     * IMPORTANT: The result is only valid if the underlying call succeeds. When using this function, make
     * sure the chain you're using it on supports the precompiled contract for modular exponentiation
     * at address 0x05 as specified in https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise,
     * the underlying function will succeed given the lack of a revert, but the result may be incorrectly
     * interpreted as 0.
     */
    function modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256) {
        (bool success, uint256 result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m).
     * It includes a success flag indicating if the operation succeeded. Operation will be marked as failed if trying
     * to operate modulo 0 or if the underlying precompile reverted.
     *
     * IMPORTANT: The result is only valid if the success flag is true. When using this function, make sure the chain
     * you're using it on supports the precompiled contract for modular exponentiation at address 0x05 as specified in
     * https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise, the underlying function will succeed given the lack
     * of a revert, but the result may be incorrectly interpreted as 0.
     */
    function tryModExp(uint256 b, uint256 e, uint256 m) internal view returns (bool success, uint256 result) {
        if (m == 0) return (false, 0);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            // | Offset    | Content    | Content (Hex)                                                      |
            // |-----------|------------|--------------------------------------------------------------------|
            // | 0x00:0x1f | size of b  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x20:0x3f | size of e  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x40:0x5f | size of m  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x60:0x7f | value of b | 0x<.............................................................b> |
            // | 0x80:0x9f | value of e | 0x<.............................................................e> |
            // | 0xa0:0xbf | value of m | 0x<.............................................................m> |
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), b)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), m)

            // Given the result < m, it's guaranteed to fit in 32 bytes,
            // so we can use the memory scratch space located at offset 0.
            success := staticcall(gas(), 0x05, ptr, 0xc0, 0x00, 0x20)
            result := mload(0x00)
        }
    }

    /**
     * @dev Variant of {modExp} that supports inputs of arbitrary length.
     */
    function modExp(bytes memory b, bytes memory e, bytes memory m) internal view returns (bytes memory) {
        (bool success, bytes memory result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Variant of {tryModExp} that supports inputs of arbitrary length.
     */
    function tryModExp(
        bytes memory b,
        bytes memory e,
        bytes memory m
    ) internal view returns (bool success, bytes memory result) {
        if (_zeroBytes(m)) return (false, new bytes(0));

        uint256 mLen = m.length;

        // Encode call args in result and move the free memory pointer
        result = abi.encodePacked(b.length, e.length, mLen, b, e, m);

        assembly ("memory-safe") {
            let dataPtr := add(result, 0x20)
            // Write result on top of args to avoid allocating extra memory.
            success := staticcall(gas(), 0x05, dataPtr, mload(result), dataPtr, mLen)
            // Overwrite the length.
            // result.length > returndatasize() is guaranteed because returndatasize() == m.length
            mstore(result, mLen)
            // Set the memory pointer after the returned data.
            mstore(0x40, add(dataPtr, mLen))
        }
    }

    /**
     * @dev Returns whether the provided byte array is zero.
     */
    function _zeroBytes(bytes memory byteArray) private pure returns (bool) {
        for (uint256 i = 0; i < byteArray.length; ++i) {
            if (byteArray[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
     *
     * This method is based on Newton's method for computing square roots; the algorithm is restricted to only
     * using integer operations.
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        unchecked {
            // Take care of easy edge cases when a == 0 or a == 1
            if (a <= 1) {
                return a;
            }

            // In this function, we use Newton's method to get a root of `f(x) := x² - a`. It involves building a
            // sequence x_n that converges toward sqrt(a). For each iteration x_n, we also define the error between
            // the current value as `ε_n = | x_n - sqrt(a) |`.
            //
            // For our first estimation, we consider `e` the smallest power of 2 which is bigger than the square root
            // of the target. (i.e. `2**(e-1) ≤ sqrt(a) < 2**e`). We know that `e ≤ 128` because `(2¹²⁸)² = 2²⁵⁶` is
            // bigger than any uint256.
            //
            // By noticing that
            // `2**(e-1) ≤ sqrt(a) < 2**e → (2**(e-1))² ≤ a < (2**e)² → 2**(2*e-2) ≤ a < 2**(2*e)`
            // we can deduce that `e - 1` is `log2(a) / 2`. We can thus compute `x_n = 2**(e-1)` using a method similar
            // to the msb function.
            uint256 aa = a;
            uint256 xn = 1;

            if (aa >= (1 << 128)) {
                aa >>= 128;
                xn <<= 64;
            }
            if (aa >= (1 << 64)) {
                aa >>= 64;
                xn <<= 32;
            }
            if (aa >= (1 << 32)) {
                aa >>= 32;
                xn <<= 16;
            }
            if (aa >= (1 << 16)) {
                aa >>= 16;
                xn <<= 8;
            }
            if (aa >= (1 << 8)) {
                aa >>= 8;
                xn <<= 4;
            }
            if (aa >= (1 << 4)) {
                aa >>= 4;
                xn <<= 2;
            }
            if (aa >= (1 << 2)) {
                xn <<= 1;
            }

            // We now have x_n such that `x_n = 2**(e-1) ≤ sqrt(a) < 2**e = 2 * x_n`. This implies ε_n ≤ 2**(e-1).
            //
            // We can refine our estimation by noticing that the middle of that interval minimizes the error.
            // If we move x_n to equal 2**(e-1) + 2**(e-2), then we reduce the error to ε_n ≤ 2**(e-2).
            // This is going to be our x_0 (and ε_0)
            xn = (3 * xn) >> 1; // ε_0 := | x_0 - sqrt(a) | ≤ 2**(e-2)

            // From here, Newton's method give us:
            // x_{n+1} = (x_n + a / x_n) / 2
            //
            // One should note that:
            // x_{n+1}² - a = ((x_n + a / x_n) / 2)² - a
            //              = ((x_n² + a) / (2 * x_n))² - a
            //              = (x_n⁴ + 2 * a * x_n² + a²) / (4 * x_n²) - a
            //              = (x_n⁴ + 2 * a * x_n² + a² - 4 * a * x_n²) / (4 * x_n²)
            //              = (x_n⁴ - 2 * a * x_n² + a²) / (4 * x_n²)
            //              = (x_n² - a)² / (2 * x_n)²
            //              = ((x_n² - a) / (2 * x_n))²
            //              ≥ 0
            // Which proves that for all n ≥ 1, sqrt(a) ≤ x_n
            //
            // This gives us the proof of quadratic convergence of the sequence:
            // ε_{n+1} = | x_{n+1} - sqrt(a) |
            //         = | (x_n + a / x_n) / 2 - sqrt(a) |
            //         = | (x_n² + a - 2*x_n*sqrt(a)) / (2 * x_n) |
            //         = | (x_n - sqrt(a))² / (2 * x_n) |
            //         = | ε_n² / (2 * x_n) |
            //         = ε_n² / | (2 * x_n) |
            //
            // For the first iteration, we have a special case where x_0 is known:
            // ε_1 = ε_0² / | (2 * x_0) |
            //     ≤ (2**(e-2))² / (2 * (2**(e-1) + 2**(e-2)))
            //     ≤ 2**(2*e-4) / (3 * 2**(e-1))
            //     ≤ 2**(e-3) / 3
            //     ≤ 2**(e-3-log2(3))
            //     ≤ 2**(e-4.5)
            //
            // For the following iterations, we use the fact that, 2**(e-1) ≤ sqrt(a) ≤ x_n:
            // ε_{n+1} = ε_n² / | (2 * x_n) |
            //         ≤ (2**(e-k))² / (2 * 2**(e-1))
            //         ≤ 2**(2*e-2*k) / 2**e
            //         ≤ 2**(e-2*k)
            xn = (xn + a / xn) >> 1; // ε_1 := | x_1 - sqrt(a) | ≤ 2**(e-4.5)  -- special case, see above
            xn = (xn + a / xn) >> 1; // ε_2 := | x_2 - sqrt(a) | ≤ 2**(e-9)    -- general case with k = 4.5
            xn = (xn + a / xn) >> 1; // ε_3 := | x_3 - sqrt(a) | ≤ 2**(e-18)   -- general case with k = 9
            xn = (xn + a / xn) >> 1; // ε_4 := | x_4 - sqrt(a) | ≤ 2**(e-36)   -- general case with k = 18
            xn = (xn + a / xn) >> 1; // ε_5 := | x_5 - sqrt(a) | ≤ 2**(e-72)   -- general case with k = 36
            xn = (xn + a / xn) >> 1; // ε_6 := | x_6 - sqrt(a) | ≤ 2**(e-144)  -- general case with k = 72

            // Because e ≤ 128 (as discussed during the first estimation phase), we know have reached a precision
            // ε_6 ≤ 2**(e-144) < 1. Given we're operating on integers, then we can ensure that xn is now either
            // sqrt(a) or sqrt(a) + 1.
            return xn - SafeCast.toUint(xn > a / xn);
        }
    }

    /**
     * @dev Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && result * result < a);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // If upper 8 bits of 16-bit half set, add 8 to result
        r |= SafeCast.toUint((x >> r) > 0xff) << 3;
        // If upper 4 bits of 8-bit half set, add 4 to result
        r |= SafeCast.toUint((x >> r) > 0xf) << 2;

        // Shifts value right by the current result and use it as an index into this lookup table:
        //
        // | x (4 bits) |  index  | table[index] = MSB position |
        // |------------|---------|-----------------------------|
        // |    0000    |    0    |        table[0] = 0         |
        // |    0001    |    1    |        table[1] = 0         |
        // |    0010    |    2    |        table[2] = 1         |
        // |    0011    |    3    |        table[3] = 1         |
        // |    0100    |    4    |        table[4] = 2         |
        // |    0101    |    5    |        table[5] = 2         |
        // |    0110    |    6    |        table[6] = 2         |
        // |    0111    |    7    |        table[7] = 2         |
        // |    1000    |    8    |        table[8] = 3         |
        // |    1001    |    9    |        table[9] = 3         |
        // |    1010    |   10    |        table[10] = 3        |
        // |    1011    |   11    |        table[11] = 3        |
        // |    1100    |   12    |        table[12] = 3        |
        // |    1101    |   13    |        table[13] = 3        |
        // |    1110    |   14    |        table[14] = 3        |
        // |    1111    |   15    |        table[15] = 3        |
        //
        // The lookup table is represented as a 32-byte value with the MSB positions for 0-15 in the last 16 bytes.
        assembly ("memory-safe") {
            r := or(r, byte(shr(r, x), 0x0000010102020202030303030303030300000000000000000000000000000000))
        }
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << result < value);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 10 ** result < value);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // Add 1 if upper 8 bits of 16-bit half set, and divide accumulated result by 8
        return (r >> 3) | SafeCast.toUint((x >> r) > 0xff);
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << (result << 3) < value);
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/proxy/Clones.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (proxy/Clones.sol)

pragma solidity ^0.8.20;

import {Create2} from "../utils/Create2.sol";
import {Errors} from "../utils/Errors.sol";

/**
 * @dev https://eips.ethereum.org/EIPS/eip-1167[ERC-1167] is a standard for
 * deploying minimal proxy contracts, also known as "clones".
 *
 * > To simply and cheaply clone contract functionality in an immutable way, this standard specifies
 * > a minimal bytecode implementation that delegates all calls to a known, fixed address.
 *
 * The library includes functions to deploy a proxy using either `create` (traditional deployment) or `create2`
 * (salted deterministic deployment). It also includes functions to predict the addresses of clones deployed using the
 * deterministic method.
 */
library Clones {
    error CloneArgumentsTooLong();

    /**
     * @dev Deploys and returns the address of a clone that mimics the behavior of `implementation`.
     *
     * This function uses the create opcode, which should never revert.
     *
     * WARNING: This function does not check if `implementation` has code. A clone that points to an address
     * without code cannot be initialized. Initialization calls may appear to be successful when, in reality, they
     * have no effect and leave the clone uninitialized, allowing a third party to initialize it later.
     */
    function clone(address implementation) internal returns (address instance) {
        return clone(implementation, 0);
    }

    /**
     * @dev Same as {xref-Clones-clone-address-}[clone], but with a `value` parameter to send native currency
     * to the new contract.
     *
     * WARNING: This function does not check if `implementation` has code. A clone that points to an address
     * without code cannot be initialized. Initialization calls may appear to be successful when, in reality, they
     * have no effect and leave the clone uninitialized, allowing a third party to initialize it later.
     *
     * NOTE: Using a non-zero value at creation will require the contract using this function (e.g. a factory)
     * to always have enough balance for new deployments. Consider exposing this function under a payable method.
     */
    function clone(address implementation, uint256 value) internal returns (address instance) {
        if (address(this).balance < value) {
            revert Errors.InsufficientBalance(address(this).balance, value);
        }
        assembly ("memory-safe") {
            // Cleans the upper 96 bits of the `implementation` word, then packs the first 3 bytes
            // of the `implementation` address with the bytecode before the address.
            mstore(0x00, or(shr(0xe8, shl(0x60, implementation)), 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000))
            // Packs the remaining 17 bytes of `implementation` with the bytecode after the address.
            mstore(0x20, or(shl(0x78, implementation), 0x5af43d82803e903d91602b57fd5bf3))
            instance := create(value, 0x09, 0x37)
        }
        if (instance == address(0)) {
            revert Errors.FailedDeployment();
        }
    }

    /**
     * @dev Deploys and returns the address of a clone that mimics the behavior of `implementation`.
     *
     * This function uses the create2 opcode and a `salt` to deterministically deploy
     * the clone. Using the same `implementation` and `salt` multiple times will revert, since
     * the clones cannot be deployed twice at the same address.
     *
     * WARNING: This function does not check if `implementation` has code. A clone that points to an address
     * without code cannot be initialized. Initialization calls may appear to be successful when, in reality, they
     * have no effect and leave the clone uninitialized, allowing a third party to initialize it later.
     */
    function cloneDeterministic(address implementation, bytes32 salt) internal returns (address instance) {
        return cloneDeterministic(implementation, salt, 0);
    }

    /**
     * @dev Same as {xref-Clones-cloneDeterministic-address-bytes32-}[cloneDeterministic], but with
     * a `value` parameter to send native currency to the new contract.
     *
     * WARNING: This function does not check if `implementation` has code. A clone that points to an address
     * without code cannot be initialized. Initialization calls may appear to be successful when, in reality, they
     * have no effect and leave the clone uninitialized, allowing a third party to initialize it later.
     *
     * NOTE: Using a non-zero value at creation will require the contract using this function (e.g. a factory)
     * to always have enough balance for new deployments. Consider exposing this function under a payable method.
     */
    function cloneDeterministic(
        address implementation,
        bytes32 salt,
        uint256 value
    ) internal returns (address instance) {
        if (address(this).balance < value) {
            revert Errors.InsufficientBalance(address(this).balance, value);
        }
        assembly ("memory-safe") {
            // Cleans the upper 96 bits of the `implementation` word, then packs the first 3 bytes
            // of the `implementation` address with the bytecode before the address.
            mstore(0x00, or(shr(0xe8, shl(0x60, implementation)), 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000))
            // Packs the remaining 17 bytes of `implementation` with the bytecode after the address.
            mstore(0x20, or(shl(0x78, implementation), 0x5af43d82803e903d91602b57fd5bf3))
            instance := create2(value, 0x09, 0x37, salt)
        }
        if (instance == address(0)) {
            revert Errors.FailedDeployment();
        }
    }

    /**
     * @dev Computes the address of a clone deployed using {Clones-cloneDeterministic}.
     */
    function predictDeterministicAddress(
        address implementation,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(add(ptr, 0x38), deployer)
            mstore(add(ptr, 0x24), 0x5af43d82803e903d91602b57fd5bf3ff)
            mstore(add(ptr, 0x14), implementation)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73)
            mstore(add(ptr, 0x58), salt)
            mstore(add(ptr, 0x78), keccak256(add(ptr, 0x0c), 0x37))
            predicted := and(keccak256(add(ptr, 0x43), 0x55), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    /**
     * @dev Computes the address of a clone deployed using {Clones-cloneDeterministic}.
     */
    function predictDeterministicAddress(
        address implementation,
        bytes32 salt
    ) internal view returns (address predicted) {
        return predictDeterministicAddress(implementation, salt, address(this));
    }

    /**
     * @dev Deploys and returns the address of a clone that mimics the behavior of `implementation` with custom
     * immutable arguments. These are provided through `args` and cannot be changed after deployment. To
     * access the arguments within the implementation, use {fetchCloneArgs}.
     *
     * This function uses the create opcode, which should never revert.
     *
     * WARNING: This function does not check if `implementation` has code. A clone that points to an address
     * without code cannot be initialized. Initialization calls may appear to be successful when, in reality, they
     * have no effect and leave the clone uninitialized, allowing a third party to initialize it later.
     */
    function cloneWithImmutableArgs(address implementation, bytes memory args) internal returns (address instance) {
        return cloneWithImmutableArgs(implementation, args, 0);
    }

    /**
     * @dev Same as {xref-Clones-cloneWithImmutableArgs-address-bytes-}[cloneWithImmutableArgs], but with a `value`
     * parameter to send native currency to the new contract.
     *
     * WARNING: This function does not check if `implementation` has code. A clone that points to an address
     * without code cannot be initialized. Initialization calls may appear to be successful when, in reality, they
     * have no effect and leave the clone uninitialized, allowing a third party to initialize it later.
     *
     * NOTE: Using a non-zero value at creation will require the contract using this function (e.g. a factory)
     * to always have enough balance for new deployments. Consider exposing this function under a payable method.
     */
    function cloneWithImmutableArgs(
        address implementation,
        bytes memory args,
        uint256 value
    ) internal returns (address instance) {
        if (address(this).balance < value) {
            revert Errors.InsufficientBalance(address(this).balance, value);
        }
        bytes memory bytecode = _cloneCodeWithImmutableArgs(implementation, args);
        assembly ("memory-safe") {
            instance := create(value, add(bytecode, 0x20), mload(bytecode))
        }
        if (instance == address(0)) {
            revert Errors.FailedDeployment();
        }
    }

    /**
     * @dev Deploys and returns the address of a clone that mimics the behavior of `implementation` with custom
     * immutable arguments. These are provided through `args` and cannot be changed after deployment. To
     * access the arguments within the implementation, use {fetchCloneArgs}.
     *
     * This function uses the create2 opcode and a `salt` to deterministically deploy the clone. Using the same
     * `implementation`, `args` and `salt` multiple times will revert, since the clones cannot be deployed twice
     * at the same address.
     *
     * WARNING: This function does not check if `implementation` has code. A clone that points to an address
     * without code cannot be initialized. Initialization calls may appear to be successful when, in reality, they
     * have no effect and leave the clone uninitialized, allowing a third party to initialize it later.
     */
    function cloneDeterministicWithImmutableArgs(
        address implementation,
        bytes memory args,
        bytes32 salt
    ) internal returns (address instance) {
        return cloneDeterministicWithImmutableArgs(implementation, args, salt, 0);
    }

    /**
     * @dev Same as {xref-Clones-cloneDeterministicWithImmutableArgs-address-bytes-bytes32-}[cloneDeterministicWithImmutableArgs],
     * but with a `value` parameter to send native currency to the new contract.
     *
     * WARNING: This function does not check if `implementation` has code. A clone that points to an address
     * without code cannot be initialized. Initialization calls may appear to be successful when, in reality, they
     * have no effect and leave the clone uninitialized, allowing a third party to initialize it later.
     *
     * NOTE: Using a non-zero value at creation will require the contract using this function (e.g. a factory)
     * to always have enough balance for new deployments. Consider exposing this function under a payable method.
     */
    function cloneDeterministicWithImmutableArgs(
        address implementation,
        bytes memory args,
        bytes32 salt,
        uint256 value
    ) internal returns (address instance) {
        bytes memory bytecode = _cloneCodeWithImmutableArgs(implementation, args);
        return Create2.deploy(value, salt, bytecode);
    }

    /**
     * @dev Computes the address of a clone deployed using {Clones-cloneDeterministicWithImmutableArgs}.
     */
    function predictDeterministicAddressWithImmutableArgs(
        address implementation,
        bytes memory args,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        bytes memory bytecode = _cloneCodeWithImmutableArgs(implementation, args);
        return Create2.computeAddress(salt, keccak256(bytecode), deployer);
    }

    /**
     * @dev Computes the address of a clone deployed using {Clones-cloneDeterministicWithImmutableArgs}.
     */
    function predictDeterministicAddressWithImmutableArgs(
        address implementation,
        bytes memory args,
        bytes32 salt
    ) internal view returns (address predicted) {
        return predictDeterministicAddressWithImmutableArgs(implementation, args, salt, address(this));
    }

    /**
     * @dev Get the immutable args attached to a clone.
     *
     * - If `instance` is a clone that was deployed using `clone` or `cloneDeterministic`, this
     *   function will return an empty array.
     * - If `instance` is a clone that was deployed using `cloneWithImmutableArgs` or
     *   `cloneDeterministicWithImmutableArgs`, this function will return the args array used at
     *   creation.
     * - If `instance` is NOT a clone deployed using this library, the behavior is undefined. This
     *   function should only be used to check addresses that are known to be clones.
     */
    function fetchCloneArgs(address instance) internal view returns (bytes memory) {
        bytes memory result = new bytes(instance.code.length - 45); // revert if length is too short
        assembly ("memory-safe") {
            extcodecopy(instance, add(result, 32), 45, mload(result))
        }
        return result;
    }

    /**
     * @dev Helper that prepares the initcode of the proxy with immutable args.
     *
     * An assembly variant of this function requires copying the `args` array, which can be efficiently done using
     * `mcopy`. Unfortunately, that opcode is not available before cancun. A pure solidity implementation using
     * abi.encodePacked is more expensive but also more portable and easier to review.
     *
     * NOTE: https://eips.ethereum.org/EIPS/eip-170[EIP-170] limits the length of the contract code to 24576 bytes.
     * With the proxy code taking 45 bytes, that limits the length of the immutable args to 24531 bytes.
     */
    function _cloneCodeWithImmutableArgs(
        address implementation,
        bytes memory args
    ) private pure returns (bytes memory) {
        if (args.length > 24531) revert CloneArgumentsTooLong();
        return
            abi.encodePacked(
                hex"61",
                uint16(args.length + 45),
                hex"3d81600a3d39f3363d3d373d3d3d363d73",
                implementation,
                hex"5af43d82803e903d91602b57fd5bf3",
                args
            );
    }
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/access/Ownable.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)

pragma solidity ^0.8.20;

import {Context} from "../utils/Context.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    constructor(address initialOwner) {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}



// ============================================================
// FILE: lib/v3-core/contracts/base/Multicall.sol
// ============================================================
// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.22;

import "../interfaces/IMulticall.sol";

/**
 * @title Multicall
 * @author Uniswap
 * @notice Adopted from https://github.com/Uniswap/v3-periphery/blob/1d69caf0d6c8cfeae9acd1f34ead30018d6e6400/contracts/base/Multicall.sol
 * @notice Enables calling multiple methods in a single call to the contract
 */
abstract contract Multicall is IMulticall {
    /// @inheritdoc IMulticall
    function multicall(bytes[] calldata data) external override returns (bytes[] memory results) {
        uint256 dataLength = data.length;
        results = new bytes[](dataLength);
        for (uint256 i = 0; i < dataLength; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);

            if (!success) {
                // Next 5 lines from https://ethereum.stackexchange.com/a/83577
                if (result.length < 68) revert();
                assembly {
                    result := add(result, 0x04)
                }
                revert(abi.decode(result, (string)));
            }

            results[i] = result;
        }
    }
}



// ============================================================
// FILE: lib/v3-core/contracts/libraries/Errors.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

/**
 * @title Errors
 * @author StakeWise
 * @notice Contains all the custom errors
 */
library Errors {
    error AccessDenied();
    error InvalidShares();
    error InvalidAssets();
    error ZeroAddress();
    error CapacityExceeded();
    error InvalidCapacity();
    error InvalidSecurityDeposit();
    error InvalidFeeRecipient();
    error InvalidFeePercent();
    error NotHarvested();
    error NotCollateralized();
    error InvalidProof();
    error LowLtv();
    error InvalidPosition();
    error InvalidHealthFactor();
    error InvalidReceivedAssets();
    error InvalidTokenMeta();
    error UpgradeFailed();
    error InvalidValidators();
    error DeadlineExpired();
    error PermitInvalidSigner();
    error InvalidValidatorsRegistryRoot();
    error InvalidVault();
    error AlreadyAdded();
    error AlreadyRemoved();
    error InvalidOracles();
    error NotEnoughSignatures();
    error InvalidOracle();
    error TooEarlyUpdate();
    error InvalidAvgRewardPerSecond();
    error InvalidRewardsRoot();
    error HarvestFailed();
    error LiquidationDisabled();
    error InvalidLiqThresholdPercent();
    error InvalidLiqBonusPercent();
    error InvalidLtvPercent();
    error InvalidCheckpointIndex();
    error InvalidCheckpointValue();
    error MaxOraclesExceeded();
    error ExitRequestNotProcessed();
    error ValueNotChanged();
    error FlashLoanFailed();
    error CannotTopUpV1Validators();
    error InvalidSignatures();
    error EmptySubVaults();
    error UnclaimedAssets();
    error EjectingVault();
    error InvalidCurator();
    error RewardsNonceIsHigher();
    error InvalidRedeemablePositions();
    error RedeemablePositionsProposed();
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IOsTokenVaultEscrow.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IMulticall} from "./IMulticall.sol";

/**
 * @title IOsTokenVaultEscrow
 * @author StakeWise
 * @notice Interface for OsTokenVaultEscrow contract
 */
interface IOsTokenVaultEscrow is IMulticall {
    /**
     * @notice Struct to store the escrow position details
     * @param owner The address of the assets owner
     * @param exitedAssets The amount of assets exited and ready to be claimed
     * @param osTokenShares The amount of osToken shares
     * @param cumulativeFeePerShare The cumulative fee per share used to calculate the osToken fee
     */
    struct Position {
        address owner;
        uint96 exitedAssets;
        uint128 osTokenShares;
        uint128 cumulativeFeePerShare;
    }

    /**
     * @notice Event emitted on position creation
     * @param vault The address of the vault
     * @param exitPositionTicket The exit position ticket
     * @param owner The address of the assets owner
     * @param osTokenShares The amount of osToken shares
     * @param cumulativeFeePerShare The cumulative fee per share used to calculate the osToken fee
     */
    event PositionCreated(
        address indexed vault,
        uint256 indexed exitPositionTicket,
        address owner,
        uint256 osTokenShares,
        uint256 cumulativeFeePerShare
    );

    /**
     * @notice Event emitted on assets exit processing
     * @param vault The address of the vault
     * @param caller The address of the caller
     * @param exitPositionTicket The exit position ticket
     * @param exitedAssets The amount of exited assets claimed
     */
    event ExitedAssetsProcessed(
        address indexed vault, address indexed caller, uint256 indexed exitPositionTicket, uint256 exitedAssets
    );

    /**
     * @notice Event emitted on osToken liquidation
     * @param caller The address of the function caller
     * @param vault The address of the vault
     * @param exitPositionTicket The exit position ticket
     * @param receiver The address of the receiver of the liquidated assets
     * @param osTokenShares The amount of osToken shares to liquidate
     * @param receivedAssets The amount of assets received
     */
    event OsTokenLiquidated(
        address indexed caller,
        address indexed vault,
        uint256 indexed exitPositionTicket,
        address receiver,
        uint256 osTokenShares,
        uint256 receivedAssets
    );

    /**
     * @notice Event emitted on osToken redemption
     * @param caller The address of the function caller
     * @param vault The address of the vault
     * @param exitPositionTicket The exit position ticket
     * @param receiver The address of the receiver of the redeemed assets
     * @param osTokenShares The amount of osToken shares to redeem
     * @param receivedAssets The amount of assets received
     */
    event OsTokenRedeemed(
        address indexed caller,
        address indexed vault,
        uint256 indexed exitPositionTicket,
        address receiver,
        uint256 osTokenShares,
        uint256 receivedAssets
    );

    /**
     * @notice Event emitted on exited assets claim
     * @param receiver The address of the receiver of the exited assets
     * @param vault The address of the vault
     * @param exitPositionTicket The exit position ticket
     * @param osTokenShares The amount of osToken shares burned
     * @param assets The amount of assets claimed
     */
    event ExitedAssetsClaimed(
        address indexed receiver,
        address indexed vault,
        uint256 indexed exitPositionTicket,
        uint256 osTokenShares,
        uint256 assets
    );

    /**
     * @notice Event emitted on liquidation configuration update
     * @param liqThresholdPercent The liquidation threshold percent
     * @param liqBonusPercent The liquidation bonus percent
     */
    event LiqConfigUpdated(uint64 liqThresholdPercent, uint256 liqBonusPercent);

    /**
     * @notice Event emitted on authenticator update
     * @param newAuthenticator The address of the new authenticator
     */
    event AuthenticatorUpdated(address newAuthenticator);

    /**
     * @notice The liquidation threshold percent
     * @return The liquidation threshold percent starting from which the osToken shares can be liquidated
     */
    function liqThresholdPercent() external view returns (uint64);

    /**
     * @notice The liquidation bonus percent
     * @return The liquidation bonus percent paid for liquidating the osToken shares
     */
    function liqBonusPercent() external view returns (uint256);

    /**
     * @notice The address of the authenticator
     * @return The address of the authenticator contract
     */
    function authenticator() external view returns (address);

    /**
     * @notice Get the position details
     * @param vault The address of the vault
     * @param positionTicket The exit position ticket
     * @return owner The address of the assets owner
     * @return exitedAssets The amount of assets exited and ready to be claimed
     * @return osTokenShares The amount of osToken shares
     */
    function getPosition(address vault, uint256 positionTicket) external view returns (address, uint256, uint256);

    /**
     * @notice Registers the new escrow position
     * @param owner The address of the exited assets owner
     * @param exitPositionTicket The exit position ticket
     * @param osTokenShares The amount of osToken shares
     * @param cumulativeFeePerShare The cumulative fee per share used to calculate the osToken fee
     */
    function register(address owner, uint256 exitPositionTicket, uint256 osTokenShares, uint256 cumulativeFeePerShare)
        external;

    /**
     * @notice Claims exited assets from the vault to the escrow
     * @param vault The address of the vault
     * @param exitPositionTicket The exit position ticket
     * @param timestamp The timestamp of the exit
     * @param exitQueueIndex The index of the exit in the queue
     */
    function processExitedAssets(address vault, uint256 exitPositionTicket, uint256 timestamp, uint256 exitQueueIndex)
        external;

    /**
     * @notice Claims the exited assets from the escrow to the owner. Can only be called by the position owner.
     * @param vault The address of the vault
     * @param exitPositionTicket The exit position ticket
     * @param osTokenShares The amount of osToken shares to burn
     * @return claimedAssets The amount of assets claimed
     */
    function claimExitedAssets(address vault, uint256 exitPositionTicket, uint256 osTokenShares)
        external
        returns (uint256 claimedAssets);

    /**
     * @notice Liquidates the osToken shares
     * @param vault The address of the vault
     * @param exitPositionTicket The exit position ticket
     * @param osTokenShares The amount of osToken shares to liquidate
     * @param receiver The address of the receiver of the liquidated assets
     */
    function liquidateOsToken(address vault, uint256 exitPositionTicket, uint256 osTokenShares, address receiver)
        external;

    /**
     * @notice Redeems the osToken shares. Can only be called by the osToken redeemer.
     * @param vault The address of the vault
     * @param exitPositionTicket The exit position ticket
     * @param osTokenShares The amount of osToken shares to redeem
     * @param receiver The address of the receiver of the redeemed assets
     */
    function redeemOsToken(address vault, uint256 exitPositionTicket, uint256 osTokenShares, address receiver)
        external;

    /**
     * @notice Updates the authenticator. Can only be called by the owner.
     * @param newAuthenticator The address of the new authenticator
     */
    function setAuthenticator(address newAuthenticator) external;

    /**
     * @notice Updates the liquidation configuration. Can only be called by the owner.
     * @param _liqThresholdPercent The liquidation threshold percent
     * @param _liqBonusPercent The liquidation bonus percent
     */
    function updateLiqConfig(uint64 _liqThresholdPercent, uint256 _liqBonusPercent) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IOsTokenVaultController.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

/**
 * @title IOsTokenVaultController
 * @author StakeWise
 * @notice Defines the interface for the OsTokenVaultController contract
 */
interface IOsTokenVaultController {
    /**
     * @notice Event emitted on minting shares
     * @param vault The address of the Vault
     * @param receiver The address that received the shares
     * @param assets The number of assets collateralized
     * @param shares The number of tokens the owner received
     */
    event Mint(address indexed vault, address indexed receiver, uint256 assets, uint256 shares);

    /**
     * @notice Event emitted on burning shares
     * @param vault The address of the Vault
     * @param owner The address that owns the shares
     * @param assets The total number of assets withdrawn
     * @param shares The total number of shares burned
     */
    event Burn(address indexed vault, address indexed owner, uint256 assets, uint256 shares);

    /**
     * @notice Event emitted on state update
     * @param profitAccrued The profit accrued since the last update
     * @param treasuryShares The number of shares minted for the treasury
     * @param treasuryAssets The number of assets minted for the treasury
     */
    event StateUpdated(uint256 profitAccrued, uint256 treasuryShares, uint256 treasuryAssets);

    /**
     * @notice Event emitted on capacity update
     * @param capacity The amount after which the OsToken stops accepting deposits
     */
    event CapacityUpdated(uint256 capacity);

    /**
     * @notice Event emitted on treasury address update
     * @param treasury The new treasury address
     */
    event TreasuryUpdated(address indexed treasury);

    /**
     * @notice Event emitted on fee percent update
     * @param feePercent The new fee percent
     */
    event FeePercentUpdated(uint16 feePercent);

    /**
     * @notice Event emitted on average reward per second update
     * @param avgRewardPerSecond The new average reward per second
     */
    event AvgRewardPerSecondUpdated(uint256 avgRewardPerSecond);

    /**
     * @notice Event emitted on keeper address update
     * @param keeper The new keeper address
     */
    event KeeperUpdated(address keeper);

    /**
     * @notice The OsToken capacity
     * @return The amount after which the OsToken stops accepting deposits
     */
    function capacity() external view returns (uint256);

    /**
     * @notice The DAO treasury address that receives OsToken fees
     * @return The address of the treasury
     */
    function treasury() external view returns (address);

    /**
     * @notice The fee percent (multiplied by 100)
     * @return The fee percent applied by the OsToken on the rewards
     */
    function feePercent() external view returns (uint64);

    /**
     * @notice The address that can update avgRewardPerSecond
     * @return The address of the keeper contract
     */
    function keeper() external view returns (address);

    /**
     * @notice The average reward per second used to mint OsToken rewards
     * @return The average reward per second earned by the Vaults
     */
    function avgRewardPerSecond() external view returns (uint256);

    /**
     * @notice The fee per share used for calculating the fee for every position
     * @return The cumulative fee per share
     */
    function cumulativeFeePerShare() external view returns (uint256);

    /**
     * @notice The total number of shares controlled by the OsToken
     * @return The total number of shares
     */
    function totalShares() external view returns (uint256);

    /**
     * @notice Total assets controlled by the OsToken
     * @return The total amount of the underlying asset that is "managed" by OsToken
     */
    function totalAssets() external view returns (uint256);

    /**
     * @notice Converts assets to shares
     * @param assets The amount of assets to convert to shares
     * @return shares The amount of OsToken shares obtained when exchanging with the amount of assets provided
     */
    function convertToShares(uint256 assets) external view returns (uint256 shares);

    /**
     * @notice Converts shares to assets
     * @param shares The amount of shares to convert to assets
     * @return assets The amount of assets obtained when exchanging with the amount of OsToken shares provided
     */
    function convertToAssets(uint256 shares) external view returns (uint256 assets);

    /**
     * @notice Updates rewards and treasury fee checkpoint for the OsToken
     */
    function updateState() external;

    /**
     * @notice Mint OsToken shares. Can only be called by the registered vault.
     * @param receiver The address that will receive the shares
     * @param shares The amount of shares to mint
     * @return assets The amount of assets minted
     */
    function mintShares(address receiver, uint256 shares) external returns (uint256 assets);

    /**
     * @notice Burn shares for withdrawn assets. Can only be called by the registered vault.
     * @param owner The address that owns the shares
     * @param shares The amount of shares to burn
     * @return assets The amount of assets withdrawn
     */
    function burnShares(address owner, uint256 shares) external returns (uint256 assets);

    /**
     * @notice Update treasury address. Can only be called by the owner.
     * @param _treasury The new treasury address
     */
    function setTreasury(address _treasury) external;

    /**
     * @notice Update capacity. Can only be called by the owner.
     * @param _capacity The amount after which the OsToken stops accepting deposits
     */
    function setCapacity(uint256 _capacity) external;

    /**
     * @notice Update fee percent. Can only be called by the owner. Cannot be larger than 10 000 (100%).
     * @param _feePercent The new fee percent
     */
    function setFeePercent(uint16 _feePercent) external;

    /**
     * @notice Update keeper address. Can only be called by the owner.
     * @param _keeper The new keeper address
     */
    function setKeeper(address _keeper) external;

    /**
     * @notice Updates average reward per second. Can only be called by the keeper.
     * @param _avgRewardPerSecond The new average reward per second
     */
    function setAvgRewardPerSecond(uint256 _avgRewardPerSecond) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IOsTokenConfig.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

/**
 * @title IOsTokenConfig
 * @author StakeWise
 * @notice Defines the interface for the OsTokenConfig contract
 */
interface IOsTokenConfig {
    /**
     * @notice Emitted when OsToken minting and liquidating configuration values are updated
     * @param vault The address of the vault to update the config for. Will be zero address if it is a default config.
     * @param liqBonusPercent The new liquidation bonus percent value
     * @param liqThresholdPercent The new liquidation threshold percent value
     * @param ltvPercent The new loan-to-value (LTV) percent value
     */
    event OsTokenConfigUpdated(address vault, uint128 liqBonusPercent, uint64 liqThresholdPercent, uint64 ltvPercent);

    /**
     * @notice Emitted when the OsToken redeemer address is updated
     * @param newRedeemer The address of the new redeemer
     */
    event RedeemerUpdated(address newRedeemer);

    /**
     * @notice The OsToken minting and liquidating configuration values
     * @param liqThresholdPercent The liquidation threshold percent used to calculate health factor for OsToken position
     * @param liqBonusPercent The minimal bonus percent that liquidator earns on OsToken position liquidation
     * @param ltvPercent The percent used to calculate how much user can mint OsToken shares
     */
    struct Config {
        uint128 liqBonusPercent;
        uint64 liqThresholdPercent;
        uint64 ltvPercent;
    }

    /**
     * @notice The address of the OsToken redeemer
     * @return The address of the redeemer
     */
    function redeemer() external view returns (address);

    /**
     * @notice Returns the OsToken minting and liquidating configuration values for the vault
     * @param vault The address of the vault to get the config for
     * @return config The OsToken config for the vault
     */
    function getConfig(address vault) external view returns (Config memory config);

    /**
     * @notice Sets the OsToken redeemer address. Can only be called by the owner.
     * @param newRedeemer The address of the new redeemer
     */
    function setRedeemer(address newRedeemer) external;

    /**
     * @notice Updates the OsToken minting and liquidating configuration values. Can only be called by the owner.
     * @param vault The address of the vault. Set to zero address to update the default config.
     * @param config The new OsToken configuration
     */
    function updateConfig(address vault, Config memory config) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IOsTokenFlashLoans.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

/**
 * @title IOsTokenFlashLoans
 * @author StakeWise
 * @notice Interface for OsTokenFlashLoans contract
 */
interface IOsTokenFlashLoans {
    /**
     * @notice Event emitted on flash loan
     * @param caller The address of the caller
     * @param amount The flashLoan osToken shares amount
     */
    event OsTokenFlashLoan(address indexed caller, uint256 amount);

    /**
     * @notice Flash loan OsToken shares
     * @param osTokenShares The flashLoan osToken shares amount
     * @param userData Arbitrary data passed to the `IOsTokenFlashLoanRecipient.receiveFlashLoan` function
     */
    function flashLoan(uint256 osTokenShares, bytes memory userData) external;
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IOsTokenFlashLoanRecipient.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

/**
 * @title IOsTokenFlashLoanRecipient
 * @author StakeWise
 * @notice Interface for OsTokenFlashLoanRecipient contract
 */
interface IOsTokenFlashLoanRecipient {
    /**
     * @notice Receive flash loan hook
     * @param osTokenShares The osToken flash loan amount
     * @param userData Arbitrary data passed to the hook
     */
    function receiveFlashLoan(uint256 osTokenShares, bytes memory userData) external;
}



// ============================================================
// FILE: src/leverage/interfaces/IBalancerVault.sol
// ============================================================
// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.26;

/**
 * @title IBalancerVault
 * @author Balancer
 * @notice Interface for the Balancer Vault contract
 */
interface IBalancerVault {
    enum SwapKind {
        GIVEN_IN,
        GIVEN_OUT
    }

    /**
     * @dev Data for a single swap executed by `swap`. `amount` is either `amountIn` or `amountOut` depending on
     * the `kind` value.
     *
     * `assetIn` and `assetOut` are either token addresses, or the IAsset sentinel value for ETH (the zero address).
     * Note that Pools never interact with ETH directly: it will be wrapped to or unwrapped from WETH by the Vault.
     *
     * The `userData` field is ignored by the Vault, but forwarded to the Pool in the `onSwap` hook, and may be
     * used to extend swap behavior.
     */
    struct SingleSwap {
        bytes32 poolId;
        SwapKind kind;
        address assetIn;
        address assetOut;
        uint256 amount;
        bytes userData;
    }

    /**
     * @dev All tokens in a swap are either sent from the `sender` account to the Vault, or from the Vault to the
     * `recipient` account.
     *
     * If the caller is not `sender`, it must be an authorized relayer for them.
     *
     * If `fromInternalBalance` is true, the `sender`'s Internal Balance will be preferred, performing an ERC20
     * transfer for the difference between the requested amount and the User's Internal Balance (if any). The `sender`
     * must have allowed the Vault to use their tokens via `IERC20.approve()`. This matches the behavior of
     * `joinPool`.
     *
     * If `toInternalBalance` is true, tokens will be deposited to `recipient`'s internal balance instead of
     * transferred. This matches the behavior of `exitPool`.
     *
     * Note that ETH cannot be deposited to or withdrawn from Internal Balance: attempting to do so will trigger a
     * revert.
     */
    struct FundManagement {
        address sender;
        bool fromInternalBalance;
        address payable recipient;
        bool toInternalBalance;
    }

    /**
     * @dev Performs a swap with a single Pool.
     *
     * If the swap is 'given in' (the number of tokens to send to the Pool is known), it returns the amount of tokens
     * taken from the Pool, which must be greater than or equal to `limit`.
     *
     * If the swap is 'given out' (the number of tokens to take from the Pool is known), it returns the amount of tokens
     * sent to the Pool, which must be less than or equal to `limit`.
     *
     * Internal Balance usage and the recipient are determined by the `funds` struct.
     *
     * Emits a `Swap` event.
     */
    function swap(
        SingleSwap memory singleSwap,
        FundManagement memory funds,
        uint256 limit,
        uint256 deadline
    ) external payable returns (uint256);
}



// ============================================================
// FILE: src/leverage/interfaces/ILeverageStrategy.sol
// ============================================================
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity ^0.8.26;

import {IKeeperRewards} from '@stakewise-core/interfaces/IKeeperRewards.sol';
import {IOsTokenFlashLoanRecipient} from '@stakewise-core/interfaces/IOsTokenFlashLoanRecipient.sol';
import {IStrategy} from '../../interfaces/IStrategy.sol';

/**
 * @title ILeverageStrategy
 * @author StakeWise
 * @notice Interface for LeverageStrategy contract
 */
interface ILeverageStrategy is IOsTokenFlashLoanRecipient, IStrategy {
    error InvalidFlashloanAction();
    error InvalidMaxSlippagePercent();
    error ExitQueueNotEntered();
    error InvalidExitQueuePercent();
    error InvalidExitQueueTicket();
    error InvalidBalancerPoolId();

    /**
     * @notice Enum for flashloan actions
     * @param Deposit Deposit assets
     * @param ClaimExitedAssets Claim exited assets
     * @param RescueVaultAssets Rescue vault assets
     * @param RescueLendingAssets Rescue lending assets
     */
    enum FlashloanAction {
        Deposit,
        ClaimExitedAssets,
        RescueVaultAssets,
        RescueLendingAssets
    }

    /**
     * @notice Struct to store the exit position
     * @param positionTicket The exit position ticket
     * @param timestamp The timestamp of the exit position
     * @param exitQueueIndex The index of the exit position in the processed queue
     */
    struct ExitPosition {
        uint256 positionTicket;
        uint256 timestamp;
        uint256 exitQueueIndex;
    }

    /**
     * @notice Event emitted when the strategy proxy is created
     * @param strategyProxyId The id of the strategy proxy
     * @param vault The address of the vault
     * @param user The address of the user
     * @param proxy The address of the proxy created
     */
    event StrategyProxyCreated(
        bytes32 indexed strategyProxyId, address indexed vault, address indexed user, address proxy
    );

    /**
     * @notice Deposit assets to the strategy
     * @param vault The address of the vault
     * @param user The address of the user
     * @param osTokenShares Amount of osToken shares to deposit
     * @param leverageOsTokenShares Amount of osToken shares leveraged
     * @param referrer The address of the referrer
     */
    event Deposited(
        address indexed vault,
        address indexed user,
        uint256 osTokenShares,
        uint256 leverageOsTokenShares,
        address referrer
    );

    /**
     * @notice Enter the OsToken escrow exit queue
     * @param vault The address of the vault
     * @param user The address of the user
     * @param positionTicket The exit position ticket
     * @param timestamp The timestamp of the exit position ticket
     * @param osTokenShares The amount of osToken shares to exit
     * @param positionPercent The percent of the position that is exiting from strategy
     */
    event ExitQueueEntered(
        address indexed vault,
        address indexed user,
        uint256 positionTicket,
        uint256 timestamp,
        uint256 osTokenShares,
        uint256 positionPercent
    );

    /**
     * @notice Claim exited assets
     * @param osTokenShares The amount of osToken shares claimed by the user
     * @param assets The amount of assets claimed by the user
     */
    event ExitedAssetsClaimed(address indexed vault, address indexed user, uint256 osTokenShares, uint256 assets);

    /**
     * @notice Event emitted when the strategy proxy is upgraded
     * @param vault The address of the vault
     * @param user The address of the user
     * @param strategy The address of the new strategy
     */
    event StrategyProxyUpgraded(address indexed vault, address indexed user, address strategy);

    /**
     * @notice Event emitted when the vault assets are rescued
     * @param vault The address of the vault
     * @param user The address of the user
     * @param osTokenShares The amount of osToken shares rescued
     * @param assets The amount of assets rescued
     */
    event VaultAssetsRescued(address indexed vault, address indexed user, uint256 osTokenShares, uint256 assets);

    /**
     * @notice Event emitted when the lending assets are rescued
     * @param vault The address of the vault
     * @param user The address of the user
     * @param osTokenShares The amount of osToken shares rescued
     * @param assets The amount of assets rescued
     */
    event LendingAssetsRescued(address indexed vault, address indexed user, uint256 osTokenShares, uint256 assets);

    /**
     * @notice Event emitted when the strategy proxy is set to exiting state
     * @param proxy The address of the strategy proxy
     * @param isExiting True if the proxy is exiting, false otherwise
     */
    event StrategyProxyExitingUpdated(address indexed proxy, bool isExiting);

    /**
     * @notice Get the strategy proxy address
     * @param vault The address of the vault
     * @param user The address of the user
     * @return proxy The address of the strategy proxy
     */
    function getStrategyProxy(address vault, address user) external view returns (address proxy);

    /**
     * @notice Returns the vault LTV.
     * @param vault The address of the vault
     * @return The vault LTV
     */
    function getVaultLtv(
        address vault
    ) external view returns (uint256);

    /**
     * @notice Returns the borrow LTV.
     * @return The borrow LTV
     */
    function getBorrowLtv() external view returns (uint256);

    /**
     * @notice Returns the borrow position state for the proxy
     * @param proxy The address of the strategy proxy
     * @return borrowedAssets The amount of borrowed assets
     * @return suppliedOsTokenShares The amount of supplied osToken shares
     */
    function getBorrowState(
        address proxy
    ) external view returns (uint256 borrowedAssets, uint256 suppliedOsTokenShares);

    /**
     * @notice Returns the vault position state for the proxy
     * @param vault The address of the vault
     * @param proxy The address of the strategy proxy
     * @return stakedAssets The amount of staked assets
     * @return mintedOsTokenShares The amount of minted osToken shares
     */
    function getVaultState(
        address vault,
        address proxy
    ) external view returns (uint256 stakedAssets, uint256 mintedOsTokenShares);

    /**
     * @dev Checks whether the user can be forced to the exit queue
     * @param vault The address of the vault
     * @param user The address of the user
     * @return True if the user can be forced to the exit queue, otherwise false
     */
    function canForceEnterExitQueue(address vault, address user) external view returns (bool);

    /**
     * @notice Checks if the proxy is exiting
     * @param proxy The address of the proxy
     * @return isExiting True if the proxy is exiting
     */
    function isStrategyProxyExiting(
        address proxy
    ) external view returns (bool isExiting);

    /**
     * @notice Calculates the amount of osToken shares to flashloan
     * @param vault The address of the vault
     * @param osTokenShares The amount of osToken shares at hand
     * @return The amount of osToken shares to flashloan
     */
    function getFlashloanOsTokenShares(address vault, uint256 osTokenShares) external view returns (uint256);

    /**
     * @notice Updates the vault state
     * @param vault The address of the vault
     * @param harvestParams The harvest parameters
     */
    function updateVaultState(address vault, IKeeperRewards.HarvestParams calldata harvestParams) external;

    /**
     * @notice Approves the osToken transfers from the user to the strategy
     * @param vault The address of the vault
     * @param osTokenShares Amount of osToken shares to approve
     * @param deadline Unix timestamp after which the transaction will revert
     * @param v ECDSA signature v
     * @param r ECDSA signature r
     * @param s ECDSA signature s
     */
    function permit(address vault, uint256 osTokenShares, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;

    /**
     * @notice Deposit assets to the strategy
     * @param vault The address of the vault
     * @param osTokenShares Amount of osToken shares to deposit
     * @param referrer The address of the referrer
     */
    function deposit(address vault, uint256 osTokenShares, address referrer) external;

    /**
     * @notice Enter the OsToken escrow exit queue. Can only be called by the position owner.
     * @param vault The address of the vault
     * @param positionPercent The percent of the position to exit from strategy
     * @return positionTicket The exit position ticket
     */
    function enterExitQueue(address vault, uint256 positionPercent) external returns (uint256 positionTicket);

    /**
     * @notice Force enter the OsToken escrow exit queue. Can be called by anyone if approaching liquidation.
     * @param vault The address of the vault
     * @param user The address of the user
     * @return positionTicket The exit position ticket
     */
    function forceEnterExitQueue(address vault, address user) external returns (uint256 positionTicket);

    /**
     * @notice Claim exited assets. Can be called by anyone.
     * @param vault The address of the vault
     * @param user The address of the user
     * @param exitPosition The exit position to process
     */
    function claimExitedAssets(address vault, address user, ExitPosition calldata exitPosition) external;

    /**
     * @notice Rescue vault assets. Can only be called by the position owner to rescue the vault assets in case of lending protocol liquidation.
     * @param vault The address of the vault
     * @param exitPosition The exit position to process
     */
    function rescueVaultAssets(address vault, ExitPosition calldata exitPosition) external;

    /**
     * @notice Rescue lending assets. Can only be called by the position owner to rescue the lending assets in case of vault liquidation.
     * @param vault The address of the vault
     * @param assets The amount of assets to repay
     * @param maxSlippagePercent The maximum slippage percent
     */
    function rescueLendingAssets(address vault, uint256 assets, uint256 maxSlippagePercent) external;

    /**
     * @notice Set the strategy proxy exiting state. Can only be called by the proxy owner, i.e. previous strategy.
     * @param proxy The address of the strategy proxy
     */
    function setStrategyProxyExiting(
        address proxy
    ) external;

    /**
     * @notice Upgrade the strategy proxy. Can only be called by the proxy owner.
     * @param vault The address of the vault
     */
    function upgradeProxy(
        address vault
    ) external;
}



// ============================================================
// FILE: src/interfaces/IStrategiesRegistry.sol
// ============================================================
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity ^0.8.26;

/**
 * @title IStrategiesRegistry
 * @author StakeWise
 * @notice Defines the interface for the StrategiesRegistry contract
 */
interface IStrategiesRegistry {
    error InvalidStrategyId();
    error InvalidStrategyProxyId();

    /**
     * @notice Event emitted on a Strategy update
     * @param caller The address that called the function
     * @param strategy The address of the updated strategy
     * @param enabled The new status of the strategy
     */
    event StrategyUpdated(address indexed caller, address strategy, bool enabled);

    /**
     * @notice Event emitted on adding Strategy proxy contract
     * @param strategy The address of the Strategy that added the proxy
     * @param strategyProxyId The ID of the added proxy
     * @param proxy The address of the added proxy
     */
    event StrategyProxyAdded(address indexed strategy, bytes32 indexed strategyProxyId, address indexed proxy);

    /**
     * @notice Event emitted on updating the strategy configuration
     * @param strategyId The ID of the strategy to update the configuration
     * @param configName The name of the configuration to update
     * @param value The new value of the configuration
     */
    event StrategyConfigUpdated(bytes32 indexed strategyId, string configName, bytes value);

    /**
     * @notice Registered Strategies
     * @param strategy The address of the strategy to check whether it is registered
     * @return `true` for the registered Strategy, `false` otherwise
     */
    function strategies(
        address strategy
    ) external view returns (bool);

    /**
     * @notice Get the strategy proxy address based on the strategy proxy ID
     * @param strategyProxyId The ID of the strategy proxy to get the address
     * @return The address of the strategy proxy
     */
    function strategyProxyIdToProxy(
        bytes32 strategyProxyId
    ) external view returns (address);

    /**
     * @notice Registered Strategy Proxies
     * @param proxy The address of the proxy to check whether it is registered
     * @return `true` for the registered Strategy proxy, `false` otherwise
     */
    function strategyProxies(
        address proxy
    ) external view returns (bool);

    /**
     * @notice Get strategy configuration
     * @param strategyId The ID of the strategy to get the configuration
     * @param configName The name of the configuration
     * @return value The value of the configuration
     */
    function getStrategyConfig(
        bytes32 strategyId,
        string calldata configName
    ) external view returns (bytes memory value);

    /**
     * @notice Set strategy configuration. Can only be called by the owner.
     * @param strategyId The ID of the strategy to set the configuration
     * @param configName The name of the configuration
     * @param value The value of the configuration
     */
    function setStrategyConfig(bytes32 strategyId, string calldata configName, bytes calldata value) external;

    /**
     * @notice Function for enabling/disabling the Strategy. Can only be called by the owner.
     * @param strategy The address of the strategy to enable/disable
     * @param enabled The new status of the strategy
     */
    function setStrategy(address strategy, bool enabled) external;

    /**
     * @notice Function for adding Strategy proxy contract. Can only be called by the registered strategy.
     * @param strategyProxyId The ID of the proxy to add
     * @param proxy The address of the proxy to add
     */
    function addStrategyProxy(bytes32 strategyProxyId, address proxy) external;

    /**
     * @notice Function for initializing the registry. Can only be called once during the deployment.
     * @param _owner The address of the owner of the contract
     */
    function initialize(
        address _owner
    ) external;
}



// ============================================================
// FILE: lib/aave-v3-origin/src/contracts/interfaces/IPool.sol
// ============================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IPoolAddressesProvider} from './IPoolAddressesProvider.sol';
import {DataTypes} from '../protocol/libraries/types/DataTypes.sol';

/**
 * @title IPool
 * @author Aave
 * @notice Defines the basic interface for an Aave Pool.
 */
interface IPool {
  /**
   * @dev Emitted on supply()
   * @param reserve The address of the underlying asset of the reserve
   * @param user The address initiating the supply
   * @param onBehalfOf The beneficiary of the supply, receiving the aTokens
   * @param amount The amount supplied
   * @param referralCode The referral code used
   */
  event Supply(
    address indexed reserve,
    address user,
    address indexed onBehalfOf,
    uint256 amount,
    uint16 indexed referralCode
  );

  /**
   * @dev Emitted on withdraw()
   * @param reserve The address of the underlying asset being withdrawn
   * @param user The address initiating the withdrawal, owner of aTokens
   * @param to The address that will receive the underlying
   * @param amount The amount to be withdrawn
   */
  event Withdraw(address indexed reserve, address indexed user, address indexed to, uint256 amount);

  /**
   * @dev Emitted on borrow() and flashLoan() when debt needs to be opened
   * @param reserve The address of the underlying asset being borrowed
   * @param user The address of the user initiating the borrow(), receiving the funds on borrow() or just
   * initiator of the transaction on flashLoan()
   * @param onBehalfOf The address that will be getting the debt
   * @param amount The amount borrowed out
   * @param interestRateMode The rate mode: 2 for Variable, 1 is deprecated (changed on v3.2.0)
   * @param borrowRate The numeric rate at which the user has borrowed, expressed in ray
   * @param referralCode The referral code used
   */
  event Borrow(
    address indexed reserve,
    address user,
    address indexed onBehalfOf,
    uint256 amount,
    DataTypes.InterestRateMode interestRateMode,
    uint256 borrowRate,
    uint16 indexed referralCode
  );

  /**
   * @dev Emitted on repay()
   * @param reserve The address of the underlying asset of the reserve
   * @param user The beneficiary of the repayment, getting his debt reduced
   * @param repayer The address of the user initiating the repay(), providing the funds
   * @param amount The amount repaid
   * @param useATokens True if the repayment is done using aTokens, `false` if done with underlying asset directly
   */
  event Repay(
    address indexed reserve,
    address indexed user,
    address indexed repayer,
    uint256 amount,
    bool useATokens
  );

  /**
   * @dev Emitted on borrow(), repay() and liquidationCall() when using isolated assets
   * @param asset The address of the underlying asset of the reserve
   * @param totalDebt The total isolation mode debt for the reserve
   */
  event IsolationModeTotalDebtUpdated(address indexed asset, uint256 totalDebt);

  /**
   * @dev Emitted when the user selects a certain asset category for eMode
   * @param user The address of the user
   * @param categoryId The category id
   */
  event UserEModeSet(address indexed user, uint8 categoryId);

  /**
   * @dev Emitted on setUserUseReserveAsCollateral()
   * @param reserve The address of the underlying asset of the reserve
   * @param user The address of the user enabling the usage as collateral
   */
  event ReserveUsedAsCollateralEnabled(address indexed reserve, address indexed user);

  /**
   * @dev Emitted on setUserUseReserveAsCollateral()
   * @param reserve The address of the underlying asset of the reserve
   * @param user The address of the user enabling the usage as collateral
   */
  event ReserveUsedAsCollateralDisabled(address indexed reserve, address indexed user);

  /**
   * @dev Emitted on flashLoan()
   * @param target The address of the flash loan receiver contract
   * @param initiator The address initiating the flash loan
   * @param asset The address of the asset being flash borrowed
   * @param amount The amount flash borrowed
   * @param interestRateMode The flashloan mode: 0 for regular flashloan,
   *        1 for Stable (Deprecated on v3.2.0), 2 for Variable
   * @param premium The fee flash borrowed
   * @param referralCode The referral code used
   */
  event FlashLoan(
    address indexed target,
    address initiator,
    address indexed asset,
    uint256 amount,
    DataTypes.InterestRateMode interestRateMode,
    uint256 premium,
    uint16 indexed referralCode
  );

  /**
   * @dev Emitted when a borrower is liquidated.
   * @param collateralAsset The address of the underlying asset used as collateral, to receive as result of the liquidation
   * @param debtAsset The address of the underlying borrowed asset to be repaid with the liquidation
   * @param user The address of the borrower getting liquidated
   * @param debtToCover The debt amount of borrowed `asset` the liquidator wants to cover
   * @param liquidatedCollateralAmount The amount of collateral received by the liquidator
   * @param liquidator The address of the liquidator
   * @param receiveAToken True if the liquidators wants to receive the collateral aTokens, `false` if he wants
   * to receive the underlying collateral asset directly
   */
  event LiquidationCall(
    address indexed collateralAsset,
    address indexed debtAsset,
    address indexed user,
    uint256 debtToCover,
    uint256 liquidatedCollateralAmount,
    address liquidator,
    bool receiveAToken
  );

  /**
   * @dev Emitted when the state of a reserve is updated.
   * @param reserve The address of the underlying asset of the reserve
   * @param liquidityRate The next liquidity rate
   * @param stableBorrowRate The next stable borrow rate @note deprecated on v3.2.0
   * @param variableBorrowRate The next variable borrow rate
   * @param liquidityIndex The next liquidity index
   * @param variableBorrowIndex The next variable borrow index
   */
  event ReserveDataUpdated(
    address indexed reserve,
    uint256 liquidityRate,
    uint256 stableBorrowRate,
    uint256 variableBorrowRate,
    uint256 liquidityIndex,
    uint256 variableBorrowIndex
  );

  /**
   * @dev Emitted when the deficit of a reserve is covered.
   * @param reserve The address of the underlying asset of the reserve
   * @param caller The caller that triggered the DeficitCovered event
   * @param amountCovered The amount of deficit covered
   */
  event DeficitCovered(address indexed reserve, address caller, uint256 amountCovered);

  /**
   * @dev Emitted when the protocol treasury receives minted aTokens from the accrued interest.
   * @param reserve The address of the reserve
   * @param amountMinted The amount minted to the treasury
   */
  event MintedToTreasury(address indexed reserve, uint256 amountMinted);

  /**
   * @dev Emitted when deficit is realized on a liquidation.
   * @param user The user address where the bad debt will be burned
   * @param debtAsset The address of the underlying borrowed asset to be burned
   * @param amountCreated The amount of deficit created
   */
  event DeficitCreated(address indexed user, address indexed debtAsset, uint256 amountCreated);

  /**
   * @dev Emitted when a position manager is approved by the user.
   * @param user The user address
   * @param positionManager The address of the position manager
   */
  event PositionManagerApproved(address indexed user, address indexed positionManager);

  /**
   * @dev Emitted when a position manager is revoked by the user.
   * @param user The user address
   * @param positionManager The address of the position manager
   */
  event PositionManagerRevoked(address indexed user, address indexed positionManager);

  /**
   * @notice Supplies an `amount` of underlying asset into the reserve, receiving in return overlying aTokens.
   * - E.g. User supplies 100 USDC and gets in return 100 aUSDC
   * @param asset The address of the underlying asset to supply
   * @param amount The amount to be supplied
   * @param onBehalfOf The address that will receive the aTokens, same as msg.sender if the user
   *   wants to receive them on his own wallet, or a different address if the beneficiary of aTokens
   *   is a different wallet
   * @param referralCode Code used to register the integrator originating the operation, for potential rewards.
   *   0 if the action is executed directly by the user, without any middle-man
   */
  function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;

  /**
   * @notice Supply with transfer approval of asset to be supplied done via permit function
   * see: https://eips.ethereum.org/EIPS/eip-2612 and https://eips.ethereum.org/EIPS/eip-713
   * @param asset The address of the underlying asset to supply
   * @param amount The amount to be supplied
   * @param onBehalfOf The address that will receive the aTokens, same as msg.sender if the user
   *   wants to receive them on his own wallet, or a different address if the beneficiary of aTokens
   *   is a different wallet
   * @param deadline The deadline timestamp that the permit is valid
   * @param referralCode Code used to register the integrator originating the operation, for potential rewards.
   *   0 if the action is executed directly by the user, without any middle-man
   * @param permitV The V parameter of ERC712 permit sig
   * @param permitR The R parameter of ERC712 permit sig
   * @param permitS The S parameter of ERC712 permit sig
   */
  function supplyWithPermit(
    address asset,
    uint256 amount,
    address onBehalfOf,
    uint16 referralCode,
    uint256 deadline,
    uint8 permitV,
    bytes32 permitR,
    bytes32 permitS
  ) external;

  /**
   * @notice Withdraws an `amount` of underlying asset from the reserve, burning the equivalent aTokens owned
   * E.g. User has 100 aUSDC, calls withdraw() and receives 100 USDC, burning the 100 aUSDC
   * @param asset The address of the underlying asset to withdraw
   * @param amount The underlying amount to be withdrawn
   *   - Send the value type(uint256).max in order to withdraw the whole aToken balance
   * @param to The address that will receive the underlying, same as msg.sender if the user
   *   wants to receive it on his own wallet, or a different address if the beneficiary is a
   *   different wallet
   * @return The final amount withdrawn
   */
  function withdraw(address asset, uint256 amount, address to) external returns (uint256);

  /**
   * @notice Allows users to borrow a specific `amount` of the reserve underlying asset, provided that the borrower
   * already supplied enough collateral, or he was given enough allowance by a credit delegator on the VariableDebtToken
   * - E.g. User borrows 100 USDC passing as `onBehalfOf` his own address, receiving the 100 USDC in his wallet
   *   and 100 variable debt tokens
   * @param asset The address of the underlying asset to borrow
   * @param amount The amount to be borrowed
   * @param interestRateMode 2 for Variable, 1 is deprecated on v3.2.0
   * @param referralCode The code used to register the integrator originating the operation, for potential rewards.
   *   0 if the action is executed directly by the user, without any middle-man
   * @param onBehalfOf The address of the user who will receive the debt. Should be the address of the borrower itself
   * calling the function if he wants to borrow against his own collateral, or the address of the credit delegator
   * if he has been given credit delegation allowance
   */
  function borrow(
    address asset,
    uint256 amount,
    uint256 interestRateMode,
    uint16 referralCode,
    address onBehalfOf
  ) external;

  /**
   * @notice Repays a borrowed `amount` on a specific reserve, burning the equivalent debt tokens owned
   * - E.g. User repays 100 USDC, burning 100 variable debt tokens of the `onBehalfOf` address
   * @param asset The address of the borrowed underlying asset previously borrowed
   * @param amount The amount to repay
   * - Send the value type(uint256).max in order to repay the whole debt for `asset` on the specific `debtMode`
   * @param interestRateMode 2 for Variable, 1 is deprecated on v3.2.0
   * @param onBehalfOf The address of the user who will get his debt reduced/removed. Should be the address of the
   * user calling the function if he wants to reduce/remove his own debt, or the address of any other
   * other borrower whose debt should be removed
   * @return The final amount repaid
   */
  function repay(
    address asset,
    uint256 amount,
    uint256 interestRateMode,
    address onBehalfOf
  ) external returns (uint256);

  /**
   * @notice Repay with transfer approval of asset to be repaid done via permit function
   * see: https://eips.ethereum.org/EIPS/eip-2612 and https://eips.ethereum.org/EIPS/eip-713
   * @param asset The address of the borrowed underlying asset previously borrowed
   * @param amount The amount to repay
   * - Send the value type(uint256).max in order to repay the whole debt for `asset` on the specific `debtMode`
   * @param interestRateMode 2 for Variable, 1 is deprecated on v3.2.0
   * @param onBehalfOf Address of the user who will get his debt reduced/removed. Should be the address of the
   * user calling the function if he wants to reduce/remove his own debt, or the address of any other
   * other borrower whose debt should be removed
   * @param deadline The deadline timestamp that the permit is valid
   * @param permitV The V parameter of ERC712 permit sig
   * @param permitR The R parameter of ERC712 permit sig
   * @param permitS The S parameter of ERC712 permit sig
   * @return The final amount repaid
   */
  function repayWithPermit(
    address asset,
    uint256 amount,
    uint256 interestRateMode,
    address onBehalfOf,
    uint256 deadline,
    uint8 permitV,
    bytes32 permitR,
    bytes32 permitS
  ) external returns (uint256);

  /**
   * @notice Repays a borrowed `amount` on a specific reserve using the reserve aTokens, burning the
   * equivalent debt tokens
   * - E.g. User repays 100 USDC using 100 aUSDC, burning 100 variable debt tokens
   * @dev  Passing uint256.max as amount will clean up any residual aToken dust balance, if the user aToken
   * balance is not enough to cover the whole debt
   * @param asset The address of the borrowed underlying asset previously borrowed
   * @param amount The amount to repay
   * - Send the value type(uint256).max in order to repay the whole debt for `asset` on the specific `debtMode`
   * @param interestRateMode DEPRECATED in v3.2.0
   * @return The final amount repaid
   */
  function repayWithATokens(
    address asset,
    uint256 amount,
    uint256 interestRateMode
  ) external returns (uint256);

  /**
   * @notice Allows suppliers to enable/disable a specific supplied asset as collateral
   * @param asset The address of the underlying asset supplied
   * @param useAsCollateral True if the user wants to use the supply as collateral, false otherwise
   */
  function setUserUseReserveAsCollateral(address asset, bool useAsCollateral) external;

  /**
   * @notice Function to liquidate a non-healthy position collateral-wise, with Health Factor below 1
   * - The caller (liquidator) covers `debtToCover` amount of debt of the user getting liquidated, and receives
   *   a proportionally amount of the `collateralAsset` plus a bonus to cover market risk
   * @param collateralAsset The address of the underlying asset used as collateral, to receive as result of the liquidation
   * @param debtAsset The address of the underlying borrowed asset to be repaid with the liquidation
   * @param borrower The address of the borrower getting liquidated
   * @param debtToCover The debt amount of borrowed `asset` the liquidator wants to cover
   * @param receiveAToken True if the liquidators wants to receive the collateral aTokens, `false` if he wants
   * to receive the underlying collateral asset directly
   */
  function liquidationCall(
    address collateralAsset,
    address debtAsset,
    address borrower,
    uint256 debtToCover,
    bool receiveAToken
  ) external;

  /**
   * @notice Allows smartcontracts to access the liquidity of the pool within one transaction,
   * as long as the amount taken plus a fee is returned.
   * @dev IMPORTANT There are security concerns for developers of flashloan receiver contracts that must be kept
   * into consideration. For further details please visit https://docs.aave.com/developers/
   * @param receiverAddress The address of the contract receiving the funds, implementing IFlashLoanReceiver interface
   * @param assets The addresses of the assets being flash-borrowed
   * @param amounts The amounts of the assets being flash-borrowed
   * @param interestRateModes Types of the debt to open if the flash loan is not returned:
   *   0 -> Don't open any debt, just revert if funds can't be transferred from the receiver
   *   1 -> Deprecated on v3.2.0
   *   2 -> Open debt at variable rate for the value of the amount flash-borrowed to the `onBehalfOf` address
   * @param onBehalfOf The address  that will receive the debt in the case of using 2 on `modes`
   * @param params Variadic packed params to pass to the receiver as extra information
   * @param referralCode The code used to register the integrator originating the operation, for potential rewards.
   *   0 if the action is executed directly by the user, without any middle-man
   */
  function flashLoan(
    address receiverAddress,
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata interestRateModes,
    address onBehalfOf,
    bytes calldata params,
    uint16 referralCode
  ) external;

  /**
   * @notice Allows smartcontracts to access the liquidity of the pool within one transaction,
   * as long as the amount taken plus a fee is returned.
   * @dev IMPORTANT There are security concerns for developers of flashloan receiver contracts that must be kept
   * into consideration. For further details please visit https://docs.aave.com/developers/
   * @param receiverAddress The address of the contract receiving the funds, implementing IFlashLoanSimpleReceiver interface
   * @param asset The address of the asset being flash-borrowed
   * @param amount The amount of the asset being flash-borrowed
   * @param params Variadic packed params to pass to the receiver as extra information
   * @param referralCode The code used to register the integrator originating the operation, for potential rewards.
   *   0 if the action is executed directly by the user, without any middle-man
   */
  function flashLoanSimple(
    address receiverAddress,
    address asset,
    uint256 amount,
    bytes calldata params,
    uint16 referralCode
  ) external;

  /**
   * @notice Returns the user account data across all the reserves
   * @param user The address of the user
   * @return totalCollateralBase The total collateral of the user in the base currency used by the price feed
   * @return totalDebtBase The total debt of the user in the base currency used by the price feed
   * @return availableBorrowsBase The borrowing power left of the user in the base currency used by the price feed
   * @return currentLiquidationThreshold The liquidation threshold of the user
   * @return ltv The loan to value of The user
   * @return healthFactor The current health factor of the user
   */
  function getUserAccountData(
    address user
  )
    external
    view
    returns (
      uint256 totalCollateralBase,
      uint256 totalDebtBase,
      uint256 availableBorrowsBase,
      uint256 currentLiquidationThreshold,
      uint256 ltv,
      uint256 healthFactor
    );

  /**
   * @notice Initializes a reserve, activating it, assigning an aToken and debt tokens
   * @dev Only callable by the PoolConfigurator contract
   * @param asset The address of the underlying asset of the reserve
   * @param aTokenAddress The address of the aToken that will be assigned to the reserve
   * @param variableDebtAddress The address of the VariableDebtToken that will be assigned to the reserve
   */
  function initReserve(address asset, address aTokenAddress, address variableDebtAddress) external;

  /**
   * @notice Drop a reserve
   * @dev Only callable by the PoolConfigurator contract
   * @dev Does not reset eMode flags, which must be considered when reusing the same reserve id for a different reserve.
   * @param asset The address of the underlying asset of the reserve
   */
  function dropReserve(address asset) external;

  /**
   * @notice Accumulates interest to all indexes of the reserve
   * @dev Only callable by the PoolConfigurator contract
   * @dev To be used when required by the configurator, for example when updating interest rates strategy data
   * @param asset The address of the underlying asset of the reserve
   */
  function syncIndexesState(address asset) external;

  /**
   * @notice Updates interest rates on the reserve data
   * @dev Only callable by the PoolConfigurator contract
   * @dev To be used when required by the configurator, for example when updating interest rates strategy data
   * @param asset The address of the underlying asset of the reserve
   */
  function syncRatesState(address asset) external;

  /**
   * @notice Sets the configuration bitmap of the reserve as a whole
   * @dev Only callable by the PoolConfigurator contract
   * @param asset The address of the underlying asset of the reserve
   * @param configuration The new configuration bitmap
   */
  function setConfiguration(
    address asset,
    DataTypes.ReserveConfigurationMap calldata configuration
  ) external;

  /**
   * @notice Returns the configuration of the reserve
   * @param asset The address of the underlying asset of the reserve
   * @return The configuration of the reserve
   */
  function getConfiguration(
    address asset
  ) external view returns (DataTypes.ReserveConfigurationMap memory);

  /**
   * @notice Returns the configuration of the user across all the reserves
   * @param user The user address
   * @return The configuration of the user
   */
  function getUserConfiguration(
    address user
  ) external view returns (DataTypes.UserConfigurationMap memory);

  /**
   * @notice Returns the normalized income of the reserve
   * @param asset The address of the underlying asset of the reserve
   * @return The reserve's normalized income
   */
  function getReserveNormalizedIncome(address asset) external view returns (uint256);

  /**
   * @notice Returns the normalized variable debt per unit of asset
   * @dev WARNING: This function is intended to be used primarily by the protocol itself to get a
   * "dynamic" variable index based on time, current stored index and virtual rate at the current
   * moment (approx. a borrower would get if opening a position). This means that is always used in
   * combination with variable debt supply/balances.
   * If using this function externally, consider that is possible to have an increasing normalized
   * variable debt that is not equivalent to how the variable debt index would be updated in storage
   * (e.g. only updates with non-zero variable debt supply)
   * @param asset The address of the underlying asset of the reserve
   * @return The reserve normalized variable debt
   */
  function getReserveNormalizedVariableDebt(address asset) external view returns (uint256);

  /**
   * @notice Returns the state and configuration of the reserve
   * @param asset The address of the underlying asset of the reserve
   * @return The state and configuration data of the reserve
   */
  function getReserveData(address asset) external view returns (DataTypes.ReserveDataLegacy memory);

  /**
   * @notice Returns the virtual underlying balance of the reserve
   * @param asset The address of the underlying asset of the reserve
   * @return The reserve virtual underlying balance
   */
  function getVirtualUnderlyingBalance(address asset) external view returns (uint128);

  /**
   * @notice Validates and finalizes an aToken transfer
   * @dev Only callable by the overlying aToken of the `asset`
   * @param asset The address of the underlying asset of the aToken
   * @param from The user from which the aTokens are transferred
   * @param to The user receiving the aTokens
   * @param scaledAmount The scaled amount being transferred/withdrawn
   * @param scaledBalanceFromBefore The aToken scaled balance of the `from` user before the transfer
   * @param scaledBalanceToBefore The aToken scaled balance of the `to` user before the transfer
   */
  function finalizeTransfer(
    address asset,
    address from,
    address to,
    uint256 scaledAmount,
    uint256 scaledBalanceFromBefore,
    uint256 scaledBalanceToBefore
  ) external;

  /**
   * @notice Returns the list of the underlying assets of all the initialized reserves
   * @dev It does not include dropped reserves
   * @return The addresses of the underlying assets of the initialized reserves
   */
  function getReservesList() external view returns (address[] memory);

  /**
   * @notice Returns the number of initialized reserves
   * @dev It includes dropped reserves
   * @return The count
   */
  function getReservesCount() external view returns (uint256);

  /**
   * @notice Returns the address of the underlying asset of a reserve by the reserve id as stored in the DataTypes.ReserveData struct
   * @param id The id of the reserve as stored in the DataTypes.ReserveData struct
   * @return The address of the reserve associated with id
   */
  function getReserveAddressById(uint16 id) external view returns (address);

  /**
   * @notice Returns the PoolAddressesProvider connected to this contract
   * @return The address of the PoolAddressesProvider
   */
  function ADDRESSES_PROVIDER() external view returns (IPoolAddressesProvider);

  /**
   * @notice Returns the ReserveInterestRateStrategy connected to all the reserves
   * @return The address of the ReserveInterestRateStrategy contract
   */
  function RESERVE_INTEREST_RATE_STRATEGY() external view returns (address);

  /**
   * @notice Updates flash loan premium. All this premium is collected by the protocol treasury.
   * @dev The premium is calculated on the total borrowed amount
   * @dev Only callable by the PoolConfigurator contract
   * @param flashLoanPremium The flash loan premium, expressed in bps
   */
  function updateFlashloanPremium(uint128 flashLoanPremium) external;

  /**
   * @notice Configures a new or alters an existing collateral configuration of an eMode.
   * @dev In eMode, the protocol allows very high borrowing power to borrow assets of the same category.
   * The category 0 is reserved as it's the default for volatile assets
   * @param id The id of the category
   * @param config The configuration of the category
   */
  function configureEModeCategory(
    uint8 id,
    DataTypes.EModeCategoryBaseConfiguration memory config
  ) external;

  /**
   * @notice Replaces the current eMode collateralBitmap.
   * @param id The id of the category
   * @param collateralBitmap The collateralBitmap of the category
   */
  function configureEModeCategoryCollateralBitmap(uint8 id, uint128 collateralBitmap) external;

  /**
   * @notice Replaces the current eMode borrowableBitmap.
   * @param id The id of the category
   * @param borrowableBitmap The borrowableBitmap of the category
   */
  function configureEModeCategoryBorrowableBitmap(uint8 id, uint128 borrowableBitmap) external;

  /**
   * @notice Returns the data of an eMode category
   * @dev DEPRECATED use independent getters instead
   * @param id The id of the category
   * @return The configuration data of the category
   */
  function getEModeCategoryData(
    uint8 id
  ) external view returns (DataTypes.EModeCategoryLegacy memory);

  /**
   * @notice Returns the label of an eMode category
   * @param id The id of the category
   * @return The label of the category
   */
  function getEModeCategoryLabel(uint8 id) external view returns (string memory);

  /**
   * @notice Returns the collateral config of an eMode category
   * @param id The id of the category
   * @return The ltv,lt,lb of the category
   */
  function getEModeCategoryCollateralConfig(
    uint8 id
  ) external view returns (DataTypes.CollateralConfig memory);

  /**
   * @notice Returns the collateralBitmap of an eMode category
   * @param id The id of the category
   * @return The collateralBitmap of the category
   */
  function getEModeCategoryCollateralBitmap(uint8 id) external view returns (uint128);

  /**
   * @notice Returns the borrowableBitmap of an eMode category
   * @param id The id of the category
   * @return The borrowableBitmap of the category
   */
  function getEModeCategoryBorrowableBitmap(uint8 id) external view returns (uint128);

  /**
   * @notice Allows a user to use the protocol in eMode
   * @param categoryId The id of the category
   */
  function setUserEMode(uint8 categoryId) external;

  /**
   * @notice Returns the eMode the user is using
   * @param user The address of the user
   * @return The eMode id
   */
  function getUserEMode(address user) external view returns (uint256);

  /**
   * @notice Resets the isolation mode total debt of the given asset to zero
   * @dev It requires the given asset has zero debt ceiling
   * @param asset The address of the underlying asset to reset the isolationModeTotalDebt
   */
  function resetIsolationModeTotalDebt(address asset) external;

  /**
   * @notice Sets the liquidation grace period of the given asset
   * @dev To enable a liquidation grace period, a timestamp in the future should be set,
   *      To disable a liquidation grace period, any timestamp in the past works, like 0
   * @param asset The address of the underlying asset to set the liquidationGracePeriod
   * @param until Timestamp when the liquidation grace period will end
   **/
  function setLiquidationGracePeriod(address asset, uint40 until) external;

  /**
   * @notice Returns the liquidation grace period of the given asset
   * @param asset The address of the underlying asset
   * @return Timestamp when the liquidation grace period will end
   **/
  function getLiquidationGracePeriod(address asset) external view returns (uint40);

  /**
   * @notice Returns the total fee on flash loans.
   * @dev From v3.4 all flashloan fees will be send to the treasury.
   * @return The total fee on flashloans
   */
  function FLASHLOAN_PREMIUM_TOTAL() external view returns (uint128);

  /**
   * @notice Returns the part of the flashloan fees sent to protocol
   * @dev From v3.4 all flashloan fees will be send to the treasury and this value
   *      is always 100_00.
   * @return The flashloan fee sent to the protocol treasury
   */
  function FLASHLOAN_PREMIUM_TO_PROTOCOL() external view returns (uint128);

  /**
   * @notice Returns the maximum number of reserves supported to be listed in this Pool
   * @return The maximum number of reserves supported
   */
  function MAX_NUMBER_RESERVES() external view returns (uint16);

  /**
   * @notice Mints the assets accrued through the reserve factor to the treasury in the form of aTokens
   * @param assets The list of reserves for which the minting needs to be executed
   */
  function mintToTreasury(address[] calldata assets) external;

  /**
   * @notice Rescue and transfer tokens locked in this contract
   * @param token The address of the token
   * @param to The address of the recipient
   * @param amount The amount of token to transfer
   */
  function rescueTokens(address token, address to, uint256 amount) external;

  /**
   * @notice Supplies an `amount` of underlying asset into the reserve, receiving in return overlying aTokens.
   * - E.g. User supplies 100 USDC and gets in return 100 aUSDC
   * @dev Deprecated: Use the `supply` function instead
   * @param asset The address of the underlying asset to supply
   * @param amount The amount to be supplied
   * @param onBehalfOf The address that will receive the aTokens, same as msg.sender if the user
   *   wants to receive them on his own wallet, or a different address if the beneficiary of aTokens
   *   is a different wallet
   * @param referralCode Code used to register the integrator originating the operation, for potential rewards.
   *   0 if the action is executed directly by the user, without any middle-man
   */
  function deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;

  /**
   * @notice It covers the deficit of a specified reserve by burning the equivalent aToken `amount` for assets
   * @dev The deficit of a reserve can occur due to situations where borrowed assets are not repaid, leading to bad debt.
   * @param asset The address of the underlying asset to cover the deficit.
   * @param amount The amount to be covered, in aToken
   * @return The amount of tokens burned
   */
  function eliminateReserveDeficit(address asset, uint256 amount) external returns (uint256);

  /**
   * @notice Approves or disapproves a position manager. This position manager will be able
   * to call the `setUserUseReserveAsCollateralOnBehalfOf` and the
   * `setUserEModeOnBehalfOf` function on behalf of the user.
   * @param positionManager The address of the position manager
   * @param approve True if the position manager should be approved, false otherwise
   */
  function approvePositionManager(address positionManager, bool approve) external;

  /**
   * @notice Renounces a position manager role for a given user.
   * @param user The address of the user
   */
  function renouncePositionManagerRole(address user) external;

  /**
   * @notice Sets the use as collateral flag for the user on the specific reserve on behalf of the user.
   * @param asset The address of the underlying asset of the reserve
   * @param useAsCollateral True if the user wants to use the reserve as collateral, false otherwise
   * @param onBehalfOf The address of the user
   */
  function setUserUseReserveAsCollateralOnBehalfOf(
    address asset,
    bool useAsCollateral,
    address onBehalfOf
  ) external;

  /**
   * @notice Sets the eMode category for the user on the specific reserve on behalf of the user.
   * @param categoryId The id of the category
   * @param onBehalfOf The address of the user
   */
  function setUserEModeOnBehalfOf(uint8 categoryId, address onBehalfOf) external;

  /*
   * @notice Returns true if the `positionManager` address is approved to use the position manager role on behalf of the user.
   * @param user The address of the user
   * @param positionManager The address of the position manager
   * @return True if the user is approved to use the position manager, false otherwise
   */
  function isApprovedPositionManager(
    address user,
    address positionManager
  ) external view returns (bool);

  /**
   * @notice Returns the current deficit of a reserve.
   * @param asset The address of the underlying asset of the reserve
   * @return The current deficit of the reserve
   */
  function getReserveDeficit(address asset) external view returns (uint256);

  /**
   * @notice Returns the aToken address of a reserve.
   * @param asset The address of the underlying asset of the reserve
   * @return The address of the aToken
   */
  function getReserveAToken(address asset) external view returns (address);

  /**
   * @notice Returns the variableDebtToken address of a reserve.
   * @param asset The address of the underlying asset of the reserve
   * @return The address of the variableDebtToken
   */
  function getReserveVariableDebtToken(address asset) external view returns (address);

  /**
   * @notice Gets the address of the external FlashLoanLogic
   */
  function getFlashLoanLogic() external view returns (address);

  /**
   * @notice Gets the address of the external BorrowLogic
   */
  function getBorrowLogic() external view returns (address);

  /**
   * @notice Gets the address of the external EModeLogic
   */
  function getEModeLogic() external view returns (address);

  /**
   * @notice Gets the address of the external LiquidationLogic
   */
  function getLiquidationLogic() external view returns (address);

  /**
   * @notice Gets the address of the external PoolLogic
   */
  function getPoolLogic() external view returns (address);

  /**
   * @notice Gets the address of the external SupplyLogic
   */
  function getSupplyLogic() external view returns (address);
}



// ============================================================
// FILE: lib/aave-v3-origin/src/contracts/interfaces/IScaledBalanceToken.sol
// ============================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IScaledBalanceToken
 * @author Aave
 * @notice Defines the basic interface for a scaled-balance token.
 */
interface IScaledBalanceToken {
  /**
   * @dev Emitted after the mint action
   * @param caller The address performing the mint
   * @param onBehalfOf The address of the user that will receive the minted tokens
   * @param value The scaled-up amount being minted (based on user entered amount and balance increase from interest)
   * @param balanceIncrease The increase in scaled-up balance since the last action of 'onBehalfOf'
   * @param index The next liquidity index of the reserve
   */
  event Mint(
    address indexed caller,
    address indexed onBehalfOf,
    uint256 value,
    uint256 balanceIncrease,
    uint256 index
  );

  /**
   * @dev Emitted after the burn action
   * @dev If the burn function does not involve a transfer of the underlying asset, the target defaults to zero address
   * @param from The address from which the tokens will be burned
   * @param target The address that will receive the underlying, if any
   * @param value The scaled-up amount being burned (user entered amount - balance increase from interest)
   * @param balanceIncrease The increase in scaled-up balance since the last action of 'from'
   * @param index The next liquidity index of the reserve
   */
  event Burn(
    address indexed from,
    address indexed target,
    uint256 value,
    uint256 balanceIncrease,
    uint256 index
  );

  /**
   * @notice Returns the scaled balance of the user.
   * @dev The scaled balance is the sum of all the updated stored balance divided by the reserve's liquidity index
   * at the moment of the update
   * @param user The user whose balance is calculated
   * @return The scaled balance of the user
   */
  function scaledBalanceOf(address user) external view returns (uint256);

  /**
   * @notice Returns the scaled balance of the user and the scaled total supply.
   * @param user The address of the user
   * @return The scaled balance of the user
   * @return The scaled total supply
   */
  function getScaledUserBalanceAndSupply(address user) external view returns (uint256, uint256);

  /**
   * @notice Returns the scaled total supply of the scaled balance token. Represents sum(debt/index)
   * @return The scaled total supply
   */
  function scaledTotalSupply() external view returns (uint256);

  /**
   * @notice Returns last index interest was accrued to the user's balance
   * @param user The address of the user
   * @return The last index interest was accrued to the user's balance, expressed in ray
   */
  function getPreviousIndex(address user) external view returns (uint256);
}



// ============================================================
// FILE: lib/aave-v3-origin/src/contracts/protocol/libraries/helpers/TokenMath.sol
// ============================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {WadRayMath} from '../../libraries/math/WadRayMath.sol';

/**
 * @title TokenMath
 * @author BGD Labs
 * @notice Provides utility functions for calculating scaled amounts and balances for aTokens and vTokens,
 *         applying specific rounding rules (floor/ceil) as per Aave v3.5's rounding improvements.
 *         The rounding behavior of the operations is in line with the ERC-4626 token standard.
 *         In practice, this means rounding in favor of the protocol.
 */
library TokenMath {
  using WadRayMath for uint256;

  /**
   * @notice Calculates the scaled amount of aTokens to mint when supplying underlying assets.
   *         The amount is rounded down to ensure the minted aTokens are less than or equal to the supplied amount.
   * @param amount The amount of underlying asset supplied.
   * @param liquidityIndex The current aToken liquidityIndex.
   * @return The scaled amount of aTokens to mint.
   */
  function getATokenMintScaledAmount(
    uint256 amount,
    uint256 liquidityIndex
  ) internal pure returns (uint256) {
    return amount.rayDivFloor(liquidityIndex);
  }

  /**
   * @notice Calculates the scaled amount of aTokens to burn when withdrawing underlying assets.
   *         The scaled amount is rounded up to ensure the user's aToken balance is sufficiently reduced.
   * @param amount The amount of underlying asset to withdraw.
   * @param liquidityIndex The current aToken liquidityIndex.
   * @return The scaled amount of aTokens to burn.
   */
  function getATokenBurnScaledAmount(
    uint256 amount,
    uint256 liquidityIndex
  ) internal pure returns (uint256) {
    return amount.rayDivCeil(liquidityIndex);
  }

  /**
   * @notice Calculates the scaled amount of aTokens to transfer.
   *         The scaled amount is rounded up to ensure the recipient receives at least the requested amount.
   * @param amount The amount of aTokens to transfer.
   * @param liquidityIndex The current aToken liquidityIndex.
   * @return The scaled amount of aTokens for transfer.
   */
  function getATokenTransferScaledAmount(
    uint256 amount,
    uint256 liquidityIndex
  ) internal pure returns (uint256) {
    return amount.rayDivCeil(liquidityIndex);
  }

  /**
   * @notice Calculates the actual aToken balance from a scaled balance and the current liquidityIndex.
   *         The balance is rounded down to prevent overaccounting.
   * @param scaledAmount The scaled aToken balance.
   * @param liquidityIndex The current aToken liquidityIndex.
   * @return The actual aToken balance.
   */
  function getATokenBalance(
    uint256 scaledAmount,
    uint256 liquidityIndex
  ) internal pure returns (uint256) {
    return scaledAmount.rayMulFloor(liquidityIndex);
  }

  /**
   * @notice Calculates the scaled amount of vTokens to mint when borrowing.
   *         The amount is rounded up to ensure the protocol never underaccounts the user's debt.
   * @param amount The amount of underlying asset borrowed.
   * @param variableBorrowIndex The current vToken variableBorrowIndex.
   * @return The scaled amount of vTokens to mint.
   */
  function getVTokenMintScaledAmount(
    uint256 amount,
    uint256 variableBorrowIndex
  ) internal pure returns (uint256) {
    return amount.rayDivCeil(variableBorrowIndex);
  }

  /**
   * @notice Calculates the scaled amount of vTokens to burn.
   *         The scaled amount is rounded down to prevent over-burning of vTokens.
   * @param amount The amount of underlying asset corresponding to the vTokens to burn.
   * @param variableBorrowIndex The current vToken variableBorrowIndex.
   * @return The scaled amount of vTokens to burn.
   */
  function getVTokenBurnScaledAmount(
    uint256 amount,
    uint256 variableBorrowIndex
  ) internal pure returns (uint256) {
    return amount.rayDivFloor(variableBorrowIndex);
  }

  /**
   * @notice Calculates the actual vToken balance (debt) from a scaled balance and the current variableBorrowIndex.
   *         The balance is rounded up to prevent underaccounting the user's debt.
   * @param scaledAmount The scaled vToken balance.
   * @param variableBorrowIndex The current vToken variableBorrowIndex.
   * @return The actual vToken balance (debt).
   */
  function getVTokenBalance(
    uint256 scaledAmount,
    uint256 variableBorrowIndex
  ) internal pure returns (uint256) {
    return scaledAmount.rayMulCeil(variableBorrowIndex);
  }
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IKeeperOracles.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

/**
 * @title IKeeperOracles
 * @author StakeWise
 * @notice Defines the interface for the KeeperOracles contract
 */
interface IKeeperOracles is IERC5267 {
    /**
     * @notice Event emitted on the oracle addition
     * @param oracle The address of the added oracle
     */
    event OracleAdded(address indexed oracle);

    /**
     * @notice Event emitted on the oracle removal
     * @param oracle The address of the removed oracle
     */
    event OracleRemoved(address indexed oracle);

    /**
     * @notice Event emitted on oracles config update
     * @param configIpfsHash The IPFS hash of the new config
     */
    event ConfigUpdated(string configIpfsHash);

    /**
     * @notice Function for verifying whether oracle is registered or not
     * @param oracle The address of the oracle to check
     * @return `true` for the registered oracle, `false` otherwise
     */
    function isOracle(address oracle) external view returns (bool);

    /**
     * @notice Total Oracles
     * @return The total number of oracles registered
     */
    function totalOracles() external view returns (uint256);

    /**
     * @notice Function for adding oracle to the set
     * @param oracle The address of the oracle to add
     */
    function addOracle(address oracle) external;

    /**
     * @notice Function for removing oracle from the set
     * @param oracle The address of the oracle to remove
     */
    function removeOracle(address oracle) external;

    /**
     * @notice Function for updating the config IPFS hash
     * @param configIpfsHash The new config IPFS hash
     */
    function updateConfig(string calldata configIpfsHash) external;
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/interfaces/draft-IERC1822.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/draft-IERC1822.sol)

pragma solidity >=0.4.16;

/**
 * @dev ERC-1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
interface IERC1822Proxiable {
    /**
     * @dev Returns the storage slot that the proxiable contract assumes is being used to store the implementation
     * address.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy.
     */
    function proxiableUUID() external view returns (bytes32);
}



// ============================================================
// FILE: lib/v3-core/contracts/interfaces/IKeeperValidators.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.22;

import {IKeeperRewards} from "./IKeeperRewards.sol";
import {IKeeperOracles} from "./IKeeperOracles.sol";

/**
 * @title IKeeperValidators
 * @author StakeWise
 * @notice Defines the interface for the Keeper validators
 */
interface IKeeperValidators is IKeeperOracles, IKeeperRewards {
    /**
     * @notice Event emitted on validators approval
     * @param vault The address of the Vault
     * @param exitSignaturesIpfsHash The IPFS hash with the validators' exit signatures
     */
    event ValidatorsApproval(address indexed vault, string exitSignaturesIpfsHash);

    /**
     * @notice Event emitted on exit signatures update
     * @param caller The address of the function caller
     * @param vault The address of the Vault
     * @param nonce The nonce used for verifying Oracles' signatures
     * @param exitSignaturesIpfsHash The IPFS hash with the validators' exit signatures
     */
    event ExitSignaturesUpdated(
        address indexed caller, address indexed vault, uint256 nonce, string exitSignaturesIpfsHash
    );

    /**
     * @notice Event emitted on validators min oracles number update
     * @param oracles The new minimum number of oracles required to approve validators
     */
    event ValidatorsMinOraclesUpdated(uint256 oracles);

    /**
     * @notice Get nonce for the next vault exit signatures update
     * @param vault The address of the Vault to get the nonce for
     * @return The nonce of the Vault for updating signatures
     */
    function exitSignaturesNonces(address vault) external view returns (uint256);

    /**
     * @notice Struct for approving registration of one or more validators
     * @param validatorsRegistryRoot The deposit data root used to verify that oracles approved validators
     * @param deadline The deadline for submitting the approval
     * @param validators The concatenation of the validators' public key, signature and deposit data root
     * @param signatures The concatenation of Oracles' signatures
     * @param exitSignaturesIpfsHash The IPFS hash with the validators' exit signatures
     */
    struct ApprovalParams {
        bytes32 validatorsRegistryRoot;
        uint256 deadline;
        bytes validators;
        bytes signatures;
        string exitSignaturesIpfsHash;
    }

    /**
     * @notice The minimum number of oracles required to update validators
     * @return The minimum number of oracles
     */
    function validatorsMinOracles() external view returns (uint256);

    /**
     * @notice Function for approving validators registration
     * @param params The parameters for approving validators registration
     */
    function approveValidators(ApprovalParams calldata params) external;

    /**
     * @notice Function for updating exit signatures for every hard fork
     * @param vault The address of the Vault to update signatures for
     * @param deadline The deadline for submitting signatures update
     * @param exitSignaturesIpfsHash The IPFS hash with the validators' exit signatures
     * @param oraclesSignatures The concatenation of Oracles' signatures
     */
    function updateExitSignatures(
        address vault,
        uint256 deadline,
        string calldata exitSignaturesIpfsHash,
        bytes calldata oraclesSignatures
    ) external;

    /**
     * @notice Function for updating validators min oracles number
     * @param _validatorsMinOracles The new minimum number of oracles required to approve validators
     */
    function setValidatorsMinOracles(uint256 _validatorsMinOracles) external;
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/interfaces/IERC1363.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC1363.sol)

pragma solidity >=0.6.2;

import {IERC20} from "./IERC20.sol";
import {IERC165} from "./IERC165.sol";

/**
 * @title IERC1363
 * @dev Interface of the ERC-1363 standard as defined in the https://eips.ethereum.org/EIPS/eip-1363[ERC-1363].
 *
 * Defines an extension interface for ERC-20 tokens that supports executing code on a recipient contract
 * after `transfer` or `transferFrom`, or code on a spender contract after `approve`, in a single transaction.
 */
interface IERC1363 is IERC20, IERC165 {
    /*
     * Note: the ERC-165 identifier for this interface is 0xb0202a11.
     * 0xb0202a11 ===
     *   bytes4(keccak256('transferAndCall(address,uint256)')) ^
     *   bytes4(keccak256('transferAndCall(address,uint256,bytes)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256,bytes)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256,bytes)'))
     */

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(address from, address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(address from, address to, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @param data Additional data with no specified format, sent in call to `spender`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value, bytes calldata data) external returns (bool);
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/utils/Panic.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/Panic.sol)

pragma solidity ^0.8.20;

/**
 * @dev Helper library for emitting standardized panic codes.
 *
 * ```solidity
 * contract Example {
 *      using Panic for uint256;
 *
 *      // Use any of the declared internal constants
 *      function foo() { Panic.GENERIC.panic(); }
 *
 *      // Alternatively
 *      function foo() { Panic.panic(Panic.GENERIC); }
 * }
 * ```
 *
 * Follows the list from https://github.com/ethereum/solidity/blob/v0.8.24/libsolutil/ErrorCodes.h[libsolutil].
 *
 * _Available since v5.1._
 */
// slither-disable-next-line unused-state
library Panic {
    /// @dev generic / unspecified error
    uint256 internal constant GENERIC = 0x00;
    /// @dev used by the assert() builtin
    uint256 internal constant ASSERT = 0x01;
    /// @dev arithmetic underflow or overflow
    uint256 internal constant UNDER_OVERFLOW = 0x11;
    /// @dev division or modulo by zero
    uint256 internal constant DIVISION_BY_ZERO = 0x12;
    /// @dev enum conversion error
    uint256 internal constant ENUM_CONVERSION_ERROR = 0x21;
    /// @dev invalid encoding in storage
    uint256 internal constant STORAGE_ENCODING_ERROR = 0x22;
    /// @dev empty array pop
    uint256 internal constant EMPTY_ARRAY_POP = 0x31;
    /// @dev array out of bounds access
    uint256 internal constant ARRAY_OUT_OF_BOUNDS = 0x32;
    /// @dev resource error (too large allocation or too large array)
    uint256 internal constant RESOURCE_ERROR = 0x41;
    /// @dev calling invalid internal function
    uint256 internal constant INVALID_INTERNAL_FUNCTION = 0x51;

    /// @dev Reverts with a panic code. Recommended to use with
    /// the internal constants with predefined codes.
    function panic(uint256 code) internal pure {
        assembly ("memory-safe") {
            mstore(0x00, 0x4e487b71)
            mstore(0x20, code)
            revert(0x1c, 0x24)
        }
    }
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/math/SafeCast.sol)
// This file was procedurally generated from scripts/generate/templates/SafeCast.js.

pragma solidity ^0.8.20;

/**
 * @dev Wrappers over Solidity's uintXX/intXX/bool casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeCast {
    /**
     * @dev Value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /**
     * @dev An int value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedIntToUint(int256 value);

    /**
     * @dev Value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);

    /**
     * @dev An uint value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedUintToInt(uint256 value);

    /**
     * @dev Returns the downcasted uint248 from uint256, reverting on
     * overflow (when the input is greater than largest uint248).
     *
     * Counterpart to Solidity's `uint248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    /**
     * @dev Returns the downcasted uint240 from uint256, reverting on
     * overflow (when the input is greater than largest uint240).
     *
     * Counterpart to Solidity's `uint240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    /**
     * @dev Returns the downcasted uint232 from uint256, reverting on
     * overflow (when the input is greater than largest uint232).
     *
     * Counterpart to Solidity's `uint232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    /**
     * @dev Returns the downcasted uint224 from uint256, reverting on
     * overflow (when the input is greater than largest uint224).
     *
     * Counterpart to Solidity's `uint224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    /**
     * @dev Returns the downcasted uint216 from uint256, reverting on
     * overflow (when the input is greater than largest uint216).
     *
     * Counterpart to Solidity's `uint216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    /**
     * @dev Returns the downcasted uint208 from uint256, reverting on
     * overflow (when the input is greater than largest uint208).
     *
     * Counterpart to Solidity's `uint208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    /**
     * @dev Returns the downcasted uint200 from uint256, reverting on
     * overflow (when the input is greater than largest uint200).
     *
     * Counterpart to Solidity's `uint200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    /**
     * @dev Returns the downcasted uint192 from uint256, reverting on
     * overflow (when the input is greater than largest uint192).
     *
     * Counterpart to Solidity's `uint192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    /**
     * @dev Returns the downcasted uint184 from uint256, reverting on
     * overflow (when the input is greater than largest uint184).
     *
     * Counterpart to Solidity's `uint184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    /**
     * @dev Returns the downcasted uint176 from uint256, reverting on
     * overflow (when the input is greater than largest uint176).
     *
     * Counterpart to Solidity's `uint176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    /**
     * @dev Returns the downcasted uint168 from uint256, reverting on
     * overflow (when the input is greater than largest uint168).
     *
     * Counterpart to Solidity's `uint168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    /**
     * @dev Returns the downcasted uint160 from uint256, reverting on
     * overflow (when the input is greater than largest uint160).
     *
     * Counterpart to Solidity's `uint160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    /**
     * @dev Returns the downcasted uint152 from uint256, reverting on
     * overflow (when the input is greater than largest uint152).
     *
     * Counterpart to Solidity's `uint152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    /**
     * @dev Returns the downcasted uint144 from uint256, reverting on
     * overflow (when the input is greater than largest uint144).
     *
     * Counterpart to Solidity's `uint144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    /**
     * @dev Returns the downcasted uint136 from uint256, reverting on
     * overflow (when the input is greater than largest uint136).
     *
     * Counterpart to Solidity's `uint136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint120 from uint256, reverting on
     * overflow (when the input is greater than largest uint120).
     *
     * Counterpart to Solidity's `uint120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    /**
     * @dev Returns the downcasted uint112 from uint256, reverting on
     * overflow (when the input is greater than largest uint112).
     *
     * Counterpart to Solidity's `uint112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    /**
     * @dev Returns the downcasted uint104 from uint256, reverting on
     * overflow (when the input is greater than largest uint104).
     *
     * Counterpart to Solidity's `uint104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    /**
     * @dev Returns the downcasted uint96 from uint256, reverting on
     * overflow (when the input is greater than largest uint96).
     *
     * Counterpart to Solidity's `uint96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    /**
     * @dev Returns the downcasted uint88 from uint256, reverting on
     * overflow (when the input is greater than largest uint88).
     *
     * Counterpart to Solidity's `uint88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    /**
     * @dev Returns the downcasted uint80 from uint256, reverting on
     * overflow (when the input is greater than largest uint80).
     *
     * Counterpart to Solidity's `uint80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    /**
     * @dev Returns the downcasted uint72 from uint256, reverting on
     * overflow (when the input is greater than largest uint72).
     *
     * Counterpart to Solidity's `uint72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint56 from uint256, reverting on
     * overflow (when the input is greater than largest uint56).
     *
     * Counterpart to Solidity's `uint56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    /**
     * @dev Returns the downcasted uint48 from uint256, reverting on
     * overflow (when the input is greater than largest uint48).
     *
     * Counterpart to Solidity's `uint48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    /**
     * @dev Returns the downcasted uint40 from uint256, reverting on
     * overflow (when the input is greater than largest uint40).
     *
     * Counterpart to Solidity's `uint40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint24 from uint256, reverting on
     * overflow (when the input is greater than largest uint24).
     *
     * Counterpart to Solidity's `uint24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int248 from int256, reverting on
     * overflow (when the input is less than smallest int248 or
     * greater than largest int248).
     *
     * Counterpart to Solidity's `int248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    /**
     * @dev Returns the downcasted int240 from int256, reverting on
     * overflow (when the input is less than smallest int240 or
     * greater than largest int240).
     *
     * Counterpart to Solidity's `int240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    /**
     * @dev Returns the downcasted int232 from int256, reverting on
     * overflow (when the input is less than smallest int232 or
     * greater than largest int232).
     *
     * Counterpart to Solidity's `int232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    /**
     * @dev Returns the downcasted int224 from int256, reverting on
     * overflow (when the input is less than smallest int224 or
     * greater than largest int224).
     *
     * Counterpart to Solidity's `int224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    /**
     * @dev Returns the downcasted int216 from int256, reverting on
     * overflow (when the input is less than smallest int216 or
     * greater than largest int216).
     *
     * Counterpart to Solidity's `int216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    /**
     * @dev Returns the downcasted int208 from int256, reverting on
     * overflow (when the input is less than smallest int208 or
     * greater than largest int208).
     *
     * Counterpart to Solidity's `int208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    /**
     * @dev Returns the downcasted int200 from int256, reverting on
     * overflow (when the input is less than smallest int200 or
     * greater than largest int200).
     *
     * Counterpart to Solidity's `int200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    /**
     * @dev Returns the downcasted int192 from int256, reverting on
     * overflow (when the input is less than smallest int192 or
     * greater than largest int192).
     *
     * Counterpart to Solidity's `int192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    /**
     * @dev Returns the downcasted int184 from int256, reverting on
     * overflow (when the input is less than smallest int184 or
     * greater than largest int184).
     *
     * Counterpart to Solidity's `int184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    /**
     * @dev Returns the downcasted int176 from int256, reverting on
     * overflow (when the input is less than smallest int176 or
     * greater than largest int176).
     *
     * Counterpart to Solidity's `int176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    /**
     * @dev Returns the downcasted int168 from int256, reverting on
     * overflow (when the input is less than smallest int168 or
     * greater than largest int168).
     *
     * Counterpart to Solidity's `int168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    /**
     * @dev Returns the downcasted int160 from int256, reverting on
     * overflow (when the input is less than smallest int160 or
     * greater than largest int160).
     *
     * Counterpart to Solidity's `int160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    /**
     * @dev Returns the downcasted int152 from int256, reverting on
     * overflow (when the input is less than smallest int152 or
     * greater than largest int152).
     *
     * Counterpart to Solidity's `int152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    /**
     * @dev Returns the downcasted int144 from int256, reverting on
     * overflow (when the input is less than smallest int144 or
     * greater than largest int144).
     *
     * Counterpart to Solidity's `int144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    /**
     * @dev Returns the downcasted int136 from int256, reverting on
     * overflow (when the input is less than smallest int136 or
     * greater than largest int136).
     *
     * Counterpart to Solidity's `int136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    /**
     * @dev Returns the downcasted int120 from int256, reverting on
     * overflow (when the input is less than smallest int120 or
     * greater than largest int120).
     *
     * Counterpart to Solidity's `int120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    /**
     * @dev Returns the downcasted int112 from int256, reverting on
     * overflow (when the input is less than smallest int112 or
     * greater than largest int112).
     *
     * Counterpart to Solidity's `int112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    /**
     * @dev Returns the downcasted int104 from int256, reverting on
     * overflow (when the input is less than smallest int104 or
     * greater than largest int104).
     *
     * Counterpart to Solidity's `int104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    /**
     * @dev Returns the downcasted int96 from int256, reverting on
     * overflow (when the input is less than smallest int96 or
     * greater than largest int96).
     *
     * Counterpart to Solidity's `int96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    /**
     * @dev Returns the downcasted int88 from int256, reverting on
     * overflow (when the input is less than smallest int88 or
     * greater than largest int88).
     *
     * Counterpart to Solidity's `int88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    /**
     * @dev Returns the downcasted int80 from int256, reverting on
     * overflow (when the input is less than smallest int80 or
     * greater than largest int80).
     *
     * Counterpart to Solidity's `int80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    /**
     * @dev Returns the downcasted int72 from int256, reverting on
     * overflow (when the input is less than smallest int72 or
     * greater than largest int72).
     *
     * Counterpart to Solidity's `int72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    /**
     * @dev Returns the downcasted int56 from int256, reverting on
     * overflow (when the input is less than smallest int56 or
     * greater than largest int56).
     *
     * Counterpart to Solidity's `int56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    /**
     * @dev Returns the downcasted int48 from int256, reverting on
     * overflow (when the input is less than smallest int48 or
     * greater than largest int48).
     *
     * Counterpart to Solidity's `int48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    /**
     * @dev Returns the downcasted int40 from int256, reverting on
     * overflow (when the input is less than smallest int40 or
     * greater than largest int40).
     *
     * Counterpart to Solidity's `int40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    /**
     * @dev Returns the downcasted int24 from int256, reverting on
     * overflow (when the input is less than smallest int24 or
     * greater than largest int24).
     *
     * Counterpart to Solidity's `int24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        // Note: Unsafe cast below is okay because `type(int256).max` is guaranteed to be positive
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }

    /**
     * @dev Cast a boolean (false or true) to a uint256 (0 or 1) with no jump.
     */
    function toUint(bool b) internal pure returns (uint256 u) {
        assembly ("memory-safe") {
            u := iszero(iszero(b))
        }
    }
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/utils/Create2.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/Create2.sol)

pragma solidity ^0.8.20;

import {Errors} from "./Errors.sol";

/**
 * @dev Helper to make usage of the `CREATE2` EVM opcode easier and safer.
 * `CREATE2` can be used to compute in advance the address where a smart
 * contract will be deployed, which allows for interesting new mechanisms known
 * as 'counterfactual interactions'.
 *
 * See the https://eips.ethereum.org/EIPS/eip-1014#motivation[EIP] for more
 * information.
 */
library Create2 {
    /**
     * @dev There's no code to deploy.
     */
    error Create2EmptyBytecode();

    /**
     * @dev Deploys a contract using `CREATE2`. The address where the contract
     * will be deployed can be known in advance via {computeAddress}.
     *
     * The bytecode for a contract can be obtained from Solidity with
     * `type(contractName).creationCode`.
     *
     * Requirements:
     *
     * - `bytecode` must not be empty.
     * - `salt` must have not been used for `bytecode` already.
     * - the factory must have a balance of at least `amount`.
     * - if `amount` is non-zero, `bytecode` must have a `payable` constructor.
     */
    function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) internal returns (address addr) {
        if (address(this).balance < amount) {
            revert Errors.InsufficientBalance(address(this).balance, amount);
        }
        if (bytecode.length == 0) {
            revert Create2EmptyBytecode();
        }
        assembly ("memory-safe") {
            addr := create2(amount, add(bytecode, 0x20), mload(bytecode), salt)
            // if no address was created, and returndata is not empty, bubble revert
            if and(iszero(addr), not(iszero(returndatasize()))) {
                let p := mload(0x40)
                returndatacopy(p, 0, returndatasize())
                revert(p, returndatasize())
            }
        }
        if (addr == address(0)) {
            revert Errors.FailedDeployment();
        }
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy}. Any change in the
     * `bytecodeHash` or `salt` will result in a new destination address.
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash) internal view returns (address) {
        return computeAddress(salt, bytecodeHash, address(this));
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy} from a contract located at
     * `deployer`. If `deployer` is this contract's address, returns the same value as {computeAddress}.
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash, address deployer) internal pure returns (address addr) {
        assembly ("memory-safe") {
            let ptr := mload(0x40) // Get free memory pointer

            // |                   | ↓ ptr ...  ↓ ptr + 0x0B (start) ...  ↓ ptr + 0x20 ...  ↓ ptr + 0x40 ...   |
            // |-------------------|---------------------------------------------------------------------------|
            // | bytecodeHash      |                                                        CCCCCCCCCCCCC...CC |
            // | salt              |                                      BBBBBBBBBBBBB...BB                   |
            // | deployer          | 000000...0000AAAAAAAAAAAAAAAAAAA...AA                                     |
            // | 0xFF              |            FF                                                             |
            // |-------------------|---------------------------------------------------------------------------|
            // | memory            | 000000...00FFAAAAAAAAAAAAAAAAAAA...AABBBBBBBBBBBBB...BBCCCCCCCCCCCCC...CC |
            // | keccak(start, 85) |            ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑ |

            mstore(add(ptr, 0x40), bytecodeHash)
            mstore(add(ptr, 0x20), salt)
            mstore(ptr, deployer) // Right-aligned with 12 preceding garbage bytes
            let start := add(ptr, 0x0b) // The hashed data starts at the final garbage byte which we will set to 0xff
            mstore8(start, 0xff)
            addr := and(keccak256(start, 85), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/utils/Errors.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/Errors.sol)

pragma solidity ^0.8.20;

/**
 * @dev Collection of common custom errors used in multiple contracts
 *
 * IMPORTANT: Backwards compatibility is not guaranteed in future versions of the library.
 * It is recommended to avoid relying on the error API for critical functionality.
 *
 * _Available since v5.1._
 */
library Errors {
    /**
     * @dev The ETH balance of the account is not enough to perform the operation.
     */
    error InsufficientBalance(uint256 balance, uint256 needed);

    /**
     * @dev A call to an address target failed. The target may have reverted.
     */
    error FailedCall();

    /**
     * @dev The deployment failed.
     */
    error FailedDeployment();

    /**
     * @dev A necessary precompile is missing.
     */
    error MissingPrecompile(address);
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/utils/Context.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}



// ============================================================
// FILE: lib/aave-v3-origin/src/contracts/interfaces/IPoolAddressesProvider.sol
// ============================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IPoolAddressesProvider
 * @author Aave
 * @notice Defines the basic interface for a Pool Addresses Provider.
 */
interface IPoolAddressesProvider {
  /**
   * @dev Emitted when the market identifier is updated.
   * @param oldMarketId The old id of the market
   * @param newMarketId The new id of the market
   */
  event MarketIdSet(string indexed oldMarketId, string indexed newMarketId);

  /**
   * @dev Emitted when the pool is updated.
   * @param oldAddress The old address of the Pool
   * @param newAddress The new address of the Pool
   */
  event PoolUpdated(address indexed oldAddress, address indexed newAddress);

  /**
   * @dev Emitted when the pool configurator is updated.
   * @param oldAddress The old address of the PoolConfigurator
   * @param newAddress The new address of the PoolConfigurator
   */
  event PoolConfiguratorUpdated(address indexed oldAddress, address indexed newAddress);

  /**
   * @dev Emitted when the price oracle is updated.
   * @param oldAddress The old address of the PriceOracle
   * @param newAddress The new address of the PriceOracle
   */
  event PriceOracleUpdated(address indexed oldAddress, address indexed newAddress);

  /**
   * @dev Emitted when the ACL manager is updated.
   * @param oldAddress The old address of the ACLManager
   * @param newAddress The new address of the ACLManager
   */
  event ACLManagerUpdated(address indexed oldAddress, address indexed newAddress);

  /**
   * @dev Emitted when the ACL admin is updated.
   * @param oldAddress The old address of the ACLAdmin
   * @param newAddress The new address of the ACLAdmin
   */
  event ACLAdminUpdated(address indexed oldAddress, address indexed newAddress);

  /**
   * @dev Emitted when the price oracle sentinel is updated.
   * @param oldAddress The old address of the PriceOracleSentinel
   * @param newAddress The new address of the PriceOracleSentinel
   */
  event PriceOracleSentinelUpdated(address indexed oldAddress, address indexed newAddress);

  /**
   * @dev Emitted when the pool data provider is updated.
   * @param oldAddress The old address of the PoolDataProvider
   * @param newAddress The new address of the PoolDataProvider
   */
  event PoolDataProviderUpdated(address indexed oldAddress, address indexed newAddress);

  /**
   * @dev Emitted when a new proxy is created.
   * @param id The identifier of the proxy
   * @param proxyAddress The address of the created proxy contract
   * @param implementationAddress The address of the implementation contract
   */
  event ProxyCreated(
    bytes32 indexed id,
    address indexed proxyAddress,
    address indexed implementationAddress
  );

  /**
   * @dev Emitted when a new non-proxied contract address is registered.
   * @param id The identifier of the contract
   * @param oldAddress The address of the old contract
   * @param newAddress The address of the new contract
   */
  event AddressSet(bytes32 indexed id, address indexed oldAddress, address indexed newAddress);

  /**
   * @dev Emitted when the implementation of the proxy registered with id is updated
   * @param id The identifier of the contract
   * @param proxyAddress The address of the proxy contract
   * @param oldImplementationAddress The address of the old implementation contract
   * @param newImplementationAddress The address of the new implementation contract
   */
  event AddressSetAsProxy(
    bytes32 indexed id,
    address indexed proxyAddress,
    address oldImplementationAddress,
    address indexed newImplementationAddress
  );

  /**
   * @notice Returns the id of the Aave market to which this contract points to.
   * @return The market id
   */
  function getMarketId() external view returns (string memory);

  /**
   * @notice Associates an id with a specific PoolAddressesProvider.
   * @dev This can be used to create an onchain registry of PoolAddressesProviders to
   * identify and validate multiple Aave markets.
   * @param newMarketId The market id
   */
  function setMarketId(string calldata newMarketId) external;

  /**
   * @notice Returns an address by its identifier.
   * @dev The returned address might be an EOA or a contract, potentially proxied
   * @dev It returns ZERO if there is no registered address with the given id
   * @param id The id
   * @return The address of the registered for the specified id
   */
  function getAddress(bytes32 id) external view returns (address);

  /**
   * @notice General function to update the implementation of a proxy registered with
   * certain `id`. If there is no proxy registered, it will instantiate one and
   * set as implementation the `newImplementationAddress`.
   * @dev IMPORTANT Use this function carefully, only for ids that don't have an explicit
   * setter function, in order to avoid unexpected consequences
   * @param id The id
   * @param newImplementationAddress The address of the new implementation
   */
  function setAddressAsProxy(bytes32 id, address newImplementationAddress) external;

  /**
   * @notice Sets an address for an id replacing the address saved in the addresses map.
   * @dev IMPORTANT Use this function carefully, as it will do a hard replacement
   * @param id The id
   * @param newAddress The address to set
   */
  function setAddress(bytes32 id, address newAddress) external;

  /**
   * @notice Returns the address of the Pool proxy.
   * @return The Pool proxy address
   */
  function getPool() external view returns (address);

  /**
   * @notice Updates the implementation of the Pool, or creates a proxy
   * setting the new `pool` implementation when the function is called for the first time.
   * @param newPoolImpl The new Pool implementation
   */
  function setPoolImpl(address newPoolImpl) external;

  /**
   * @notice Returns the address of the PoolConfigurator proxy.
   * @return The PoolConfigurator proxy address
   */
  function getPoolConfigurator() external view returns (address);

  /**
   * @notice Updates the implementation of the PoolConfigurator, or creates a proxy
   * setting the new `PoolConfigurator` implementation when the function is called for the first time.
   * @param newPoolConfiguratorImpl The new PoolConfigurator implementation
   */
  function setPoolConfiguratorImpl(address newPoolConfiguratorImpl) external;

  /**
   * @notice Returns the address of the price oracle.
   * @return The address of the PriceOracle
   */
  function getPriceOracle() external view returns (address);

  /**
   * @notice Updates the address of the price oracle.
   * @param newPriceOracle The address of the new PriceOracle
   */
  function setPriceOracle(address newPriceOracle) external;

  /**
   * @notice Returns the address of the ACL manager.
   * @return The address of the ACLManager
   */
  function getACLManager() external view returns (address);

  /**
   * @notice Updates the address of the ACL manager.
   * @param newAclManager The address of the new ACLManager
   */
  function setACLManager(address newAclManager) external;

  /**
   * @notice Returns the address of the ACL admin.
   * @return The address of the ACL admin
   */
  function getACLAdmin() external view returns (address);

  /**
   * @notice Updates the address of the ACL admin.
   * @param newAclAdmin The address of the new ACL admin
   */
  function setACLAdmin(address newAclAdmin) external;

  /**
   * @notice Returns the address of the price oracle sentinel.
   * @return The address of the PriceOracleSentinel
   */
  function getPriceOracleSentinel() external view returns (address);

  /**
   * @notice Updates the address of the price oracle sentinel.
   * @param newPriceOracleSentinel The address of the new PriceOracleSentinel
   */
  function setPriceOracleSentinel(address newPriceOracleSentinel) external;

  /**
   * @notice Returns the address of the data provider.
   * @return The address of the DataProvider
   */
  function getPoolDataProvider() external view returns (address);

  /**
   * @notice Updates the address of the data provider.
   * @param newDataProvider The address of the new DataProvider
   */
  function setPoolDataProvider(address newDataProvider) external;
}



// ============================================================
// FILE: lib/aave-v3-origin/src/contracts/protocol/libraries/types/DataTypes.sol
// ============================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library DataTypes {
  /**
   * This exists specifically to maintain the `getReserveData()` interface, since the new, internal
   * `ReserveData` struct includes the reserve's `virtualUnderlyingBalance`.
   */
  struct ReserveDataLegacy {
    //stores the reserve configuration
    ReserveConfigurationMap configuration;
    //the liquidity index. Expressed in ray
    uint128 liquidityIndex;
    //the current supply rate. Expressed in ray
    uint128 currentLiquidityRate;
    //variable borrow index. Expressed in ray
    uint128 variableBorrowIndex;
    //the current variable borrow rate. Expressed in ray
    uint128 currentVariableBorrowRate;
    // DEPRECATED on v3.2.0
    uint128 currentStableBorrowRate;
    //timestamp of last update
    uint40 lastUpdateTimestamp;
    //the id of the reserve. Represents the position in the list of the active reserves
    uint16 id;
    //aToken address
    address aTokenAddress;
    // DEPRECATED on v3.2.0
    address stableDebtTokenAddress;
    //variableDebtToken address
    address variableDebtTokenAddress;
    // DEPRECATED on v3.4.0, should use the `RESERVE_INTEREST_RATE_STRATEGY` variable from the Pool contract
    address interestRateStrategyAddress;
    //the current treasury balance, scaled
    uint128 accruedToTreasury;
    // DEPRECATED on v3.4.0
    uint128 unbacked;
    //the outstanding debt borrowed against this asset in isolation mode
    uint128 isolationModeTotalDebt;
  }

  struct ReserveData {
    //stores the reserve configuration
    ReserveConfigurationMap configuration;
    //the liquidity index. Expressed in ray
    uint128 liquidityIndex;
    //the current supply rate. Expressed in ray
    uint128 currentLiquidityRate;
    //variable borrow index. Expressed in ray
    uint128 variableBorrowIndex;
    //the current variable borrow rate. Expressed in ray
    uint128 currentVariableBorrowRate;
    /// @notice reused `__deprecatedStableBorrowRate` storage from pre 3.2
    // the current accumulate deficit in underlying tokens
    uint128 deficit;
    //timestamp of last update
    uint40 lastUpdateTimestamp;
    //the id of the reserve. Represents the position in the list of the active reserves
    uint16 id;
    //timestamp until when liquidations are not allowed on the reserve, if set to past liquidations will be allowed
    uint40 liquidationGracePeriodUntil;
    //aToken address
    address aTokenAddress;
    // DEPRECATED on v3.2.0
    address __deprecatedStableDebtTokenAddress;
    //variableDebtToken address
    address variableDebtTokenAddress;
    // DEPRECATED on v3.4.0, should use the `RESERVE_INTEREST_RATE_STRATEGY` variable from the Pool contract
    address __deprecatedInterestRateStrategyAddress;
    //the current treasury balance, scaled
    uint128 accruedToTreasury;
    // In aave 3.3.0 this storage slot contained the `unbacked`
    uint128 virtualUnderlyingBalance;
    //the outstanding debt borrowed against this asset in isolation mode
    uint128 isolationModeTotalDebt;
    //the amount of underlying accounted for by the protocol
    // DEPRECATED on v3.4.0. Moved into the same slot as accruedToTreasury for optimized storage access.
    uint128 __deprecatedVirtualUnderlyingBalance;
  }

  struct ReserveConfigurationMap {
    //bit 0-15: LTV
    //bit 16-31: Liq. threshold
    //bit 32-47: Liq. bonus
    //bit 48-55: Decimals
    //bit 56: reserve is active
    //bit 57: reserve is frozen
    //bit 58: borrowing is enabled
    //bit 59: DEPRECATED: stable rate borrowing enabled
    //bit 60: asset is paused
    //bit 61: borrowing in isolation mode is enabled
    //bit 62: siloed borrowing enabled
    //bit 63: flashloaning enabled
    //bit 64-79: reserve factor
    //bit 80-115: borrow cap in whole tokens, borrowCap == 0 => no cap
    //bit 116-151: supply cap in whole tokens, supplyCap == 0 => no cap
    //bit 152-167: liquidation protocol fee
    //bit 168-175: DEPRECATED: eMode category
    //bit 176-211: DEPRECATED: unbacked mint cap
    //bit 212-251: debt ceiling for isolation mode with (ReserveConfiguration::DEBT_CEILING_DECIMALS) decimals
    //bit 252: DEPRECATED: virtual accounting is enabled for the reserve
    //bit 253-255 unused

    uint256 data;
  }

  struct UserConfigurationMap {
    /**
     * @dev Bitmap of the users collaterals and borrows. It is divided in pairs of bits, one pair per asset.
     * The first bit indicates if an asset is used as collateral by the user, the second whether an
     * asset is borrowed by the user.
     */
    uint256 data;
  }

  // DEPRECATED: kept for backwards compatibility, might be removed in a future version
  struct EModeCategoryLegacy {
    // each eMode category has a custom ltv and liquidation threshold
    uint16 ltv;
    uint16 liquidationThreshold;
    uint16 liquidationBonus;
    // DEPRECATED
    address priceSource;
    string label;
  }

  struct CollateralConfig {
    uint16 ltv;
    uint16 liquidationThreshold;
    uint16 liquidationBonus;
  }

  struct EModeCategoryBaseConfiguration {
    uint16 ltv;
    uint16 liquidationThreshold;
    uint16 liquidationBonus;
    string label;
  }

  struct EModeCategory {
    // each eMode category has a custom ltv and liquidation threshold
    uint16 ltv;
    uint16 liquidationThreshold;
    uint16 liquidationBonus;
    uint128 collateralBitmap;
    string label;
    uint128 borrowableBitmap;
  }

  enum InterestRateMode {
    NONE,
    __DEPRECATED,
    VARIABLE
  }

  struct ReserveCache {
    uint256 currScaledVariableDebt;
    uint256 nextScaledVariableDebt;
    uint256 currLiquidityIndex;
    uint256 nextLiquidityIndex;
    uint256 currVariableBorrowIndex;
    uint256 nextVariableBorrowIndex;
    uint256 currLiquidityRate;
    uint256 currVariableBorrowRate;
    uint256 reserveFactor;
    ReserveConfigurationMap reserveConfiguration;
    address aTokenAddress;
    address variableDebtTokenAddress;
    uint40 reserveLastUpdateTimestamp;
  }

  struct ExecuteLiquidationCallParams {
    address liquidator;
    uint256 debtToCover;
    address collateralAsset;
    address debtAsset;
    address borrower;
    bool receiveAToken;
    address priceOracle;
    uint8 borrowerEModeCategory;
    address priceOracleSentinel;
    address interestRateStrategyAddress;
  }

  struct ExecuteSupplyParams {
    address user;
    address asset;
    address interestRateStrategyAddress;
    uint256 amount;
    address onBehalfOf;
    uint16 referralCode;
  }

  struct ExecuteBorrowParams {
    address asset;
    address user;
    address onBehalfOf;
    address interestRateStrategyAddress;
    uint256 amount;
    InterestRateMode interestRateMode;
    uint16 referralCode;
    bool releaseUnderlying;
    address oracle;
    uint8 userEModeCategory;
    address priceOracleSentinel;
  }

  struct ExecuteRepayParams {
    address asset;
    address user;
    address interestRateStrategyAddress;
    uint256 amount;
    InterestRateMode interestRateMode;
    address onBehalfOf;
    bool useATokens;
    address oracle;
    uint8 userEModeCategory;
  }

  struct ExecuteWithdrawParams {
    address user;
    address asset;
    address interestRateStrategyAddress;
    uint256 amount;
    address to;
    address oracle;
    uint8 userEModeCategory;
  }

  struct ExecuteEliminateDeficitParams {
    address user;
    address asset;
    address interestRateStrategyAddress;
    uint256 amount;
  }

  struct FinalizeTransferParams {
    address asset;
    address from;
    address to;
    uint256 scaledAmount;
    uint256 scaledBalanceFromBefore;
    uint256 scaledBalanceToBefore;
    address oracle;
    uint8 fromEModeCategory;
  }

  struct FlashloanParams {
    address user;
    address receiverAddress;
    address[] assets;
    uint256[] amounts;
    uint256[] interestRateModes;
    address interestRateStrategyAddress;
    address onBehalfOf;
    bytes params;
    uint16 referralCode;
    uint256 flashLoanPremium;
    address addressesProvider;
    address pool;
    uint8 userEModeCategory;
    bool isAuthorizedFlashBorrower;
  }

  struct FlashloanSimpleParams {
    address user;
    address receiverAddress;
    address asset;
    address interestRateStrategyAddress;
    uint256 amount;
    bytes params;
    uint16 referralCode;
    uint256 flashLoanPremium;
  }

  struct FlashLoanRepaymentParams {
    address user;
    uint256 amount;
    uint256 totalPremium;
    address asset;
    address interestRateStrategyAddress;
    address receiverAddress;
    uint16 referralCode;
  }

  struct CalculateUserAccountDataParams {
    UserConfigurationMap userConfig;
    address user;
    address oracle;
    uint8 userEModeCategory;
  }

  struct ValidateBorrowParams {
    ReserveCache reserveCache;
    UserConfigurationMap userConfig;
    address asset;
    address userAddress;
    uint256 amountScaled;
    InterestRateMode interestRateMode;
    address oracle;
    uint8 userEModeCategory;
    address priceOracleSentinel;
  }

  struct ValidateLiquidationCallParams {
    ReserveCache debtReserveCache;
    uint256 totalDebt;
    uint256 healthFactor;
    address priceOracleSentinel;
    address borrower;
    address liquidator;
  }

  struct CalculateInterestRatesParams {
    uint256 unbacked;
    uint256 liquidityAdded;
    uint256 liquidityTaken;
    uint256 totalDebt;
    uint256 reserveFactor;
    address reserve;
    // @notice DEPRECATED in 3.4, but kept for backwards compatibility
    bool usingVirtualBalance;
    uint256 virtualUnderlyingBalance;
  }

  struct InitReserveParams {
    address asset;
    address aTokenAddress;
    address variableDebtAddress;
    uint16 reservesCount;
    uint16 maxNumberReserves;
  }
}



// ============================================================
// FILE: lib/aave-v3-origin/src/contracts/protocol/libraries/math/WadRayMath.sol
// ============================================================
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/**
 * @title WadRayMath library
 * @author Aave
 * @notice Provides functions to perform calculations with Wad and Ray units
 * @dev Provides mul and div function for wads (decimal numbers with 18 digits of precision) and rays (decimal numbers
 * with 27 digits of precision).
 * @dev Default operations round half up (if a value is >= .5, it will be rounded up, otherwise rounded down).
 * @dev For specific rounding behaviors, functions with `Floor` and `Ceil` suffixes or a `Rounding` parameter are available.
 */
library WadRayMath {
  enum Rounding {
    Floor,
    Ceil
  }

  // HALF_WAD and HALF_RAY expressed with extended notation as constant with operations are not supported in Yul assembly
  uint256 internal constant WAD = 1e18;
  uint256 internal constant HALF_WAD = 0.5e18;

  uint256 internal constant RAY = 1e27;
  uint256 internal constant HALF_RAY = 0.5e27;

  uint256 internal constant WAD_RAY_RATIO = 1e9;

  /**
   * @dev Multiplies two wad, rounding half up to the nearest wad
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Wad
   * @param b Wad
   * @return c = a*b, in wad
   */
  function wadMul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    // to avoid overflow, a <= (type(uint256).max - HALF_WAD) / b
    assembly {
      if iszero(or(iszero(b), iszero(gt(a, div(sub(not(0), HALF_WAD), b))))) {
        revert(0, 0)
      }

      c := div(add(mul(a, b), HALF_WAD), WAD)
    }
  }

  /**
   * @dev Divides two wad, rounding half up to the nearest wad
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Wad
   * @param b Wad
   * @return c = a/b, in wad
   */
  function wadDiv(uint256 a, uint256 b) internal pure returns (uint256 c) {
    // to avoid overflow, a <= (type(uint256).max - halfB) / WAD
    assembly {
      if or(iszero(b), iszero(iszero(gt(a, div(sub(not(0), div(b, 2)), WAD))))) {
        revert(0, 0)
      }

      c := div(add(mul(a, WAD), div(b, 2)), b)
    }
  }

  function rayMul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    assembly {
      // to avoid overflow, a <= (type(uint256).max - HALF_RAY) / b
      if iszero(or(iszero(b), iszero(gt(a, div(sub(not(0), HALF_RAY), b))))) {
        revert(0, 0)
      }
      c := div(add(mul(a, b), HALF_RAY), RAY)
    }
  }

  function rayMul(uint256 a, uint256 b, Rounding rounding) internal pure returns (uint256 c) {
    if (rounding == Rounding.Floor) return rayMulFloor(a, b);
    return rayMulCeil(a, b);
  }

  function rayMulFloor(uint256 a, uint256 b) internal pure returns (uint256 c) {
    assembly {
      // Overflow check: Ensure a * b does not exceed uint256 max
      if iszero(or(iszero(b), iszero(gt(a, div(not(0), b))))) {
        revert(0, 0)
      }

      c := div(mul(a, b), RAY)
    }
  }

  function rayMulCeil(uint256 a, uint256 b) internal pure returns (uint256 c) {
    assembly {
      // Overflow check: Ensure a * b does not exceed uint256 max
      if iszero(or(iszero(b), iszero(gt(a, div(not(0), b))))) {
        revert(0, 0)
      }

      let product := mul(a, b)
      c := add(div(product, RAY), iszero(iszero(mod(product, RAY))))
    }
  }

  /**
   * @notice Divides two ray, rounding half up to the nearest ray
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Ray
   * @param b Ray
   * @return c = a raydiv b
   */
  function rayDiv(uint256 a, uint256 b) internal pure returns (uint256 c) {
    assembly {
      // to avoid overflow, a <= (type(uint256).max - b / 2) / RAY
      if or(iszero(b), iszero(iszero(gt(a, div(sub(not(0), div(b, 2)), RAY))))) {
        revert(0, 0)
      }
      c := div(add(mul(a, RAY), div(b, 2)), b)
    }
  }

  function rayDiv(uint256 a, uint256 b, Rounding rounding) internal pure returns (uint256 c) {
    if (rounding == Rounding.Floor) return rayDivFloor(a, b);
    return rayDivCeil(a, b);
  }

  function rayDivCeil(uint256 a, uint256 b) internal pure returns (uint256 c) {
    assembly {
      // Overflow check: Ensure a * RAY does not exceed uint256 max
      if or(iszero(b), iszero(iszero(gt(a, div(not(0), RAY))))) {
        revert(0, 0)
      }
      let scaled := mul(a, RAY)
      c := add(div(scaled, b), iszero(iszero(mod(scaled, b))))
    }
  }

  function rayDivFloor(uint256 a, uint256 b) internal pure returns (uint256 c) {
    assembly {
      // Overflow check: Ensure a * RAY does not exceed uint256 max
      if or(iszero(b), iszero(iszero(gt(a, div(not(0), RAY))))) {
        revert(0, 0)
      }
      c := div(mul(a, RAY), b)
    }
  }

  /**
   * @dev Casts ray down to wad
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Ray
   * @return b = a converted to wad, rounded half up to the nearest wad
   */
  function rayToWad(uint256 a) internal pure returns (uint256 b) {
    assembly {
      b := div(a, WAD_RAY_RATIO)
      let remainder := mod(a, WAD_RAY_RATIO)
      if iszero(lt(remainder, div(WAD_RAY_RATIO, 2))) {
        b := add(b, 1)
      }
    }
  }

  /**
   * @dev Converts wad up to ray
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Wad
   * @return b = a converted in ray
   */
  function wadToRay(uint256 a) internal pure returns (uint256 b) {
    // to avoid overflow, b/WAD_RAY_RATIO == a
    assembly {
      b := mul(a, WAD_RAY_RATIO)

      if iszero(eq(div(b, WAD_RAY_RATIO), a)) {
        revert(0, 0)
      }
    }
  }
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/interfaces/IERC5267.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC5267.sol)

pragma solidity >=0.4.16;

interface IERC5267 {
    /**
     * @dev MAY be emitted to signal that the domain could have changed.
     */
    event EIP712DomainChanged();

    /**
     * @dev returns the fields and values that describe the domain separator used by this contract for EIP-712
     * signature.
     */
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
}



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC20.sol)

pragma solidity >=0.4.16;

import {IERC20} from "../token/ERC20/IERC20.sol";



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/interfaces/IERC165.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC165.sol)

pragma solidity >=0.4.16;

import {IERC165} from "../utils/introspection/IERC165.sol";



// ============================================================
// FILE: lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/IERC165.sol)

pragma solidity >=0.4.16;

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
