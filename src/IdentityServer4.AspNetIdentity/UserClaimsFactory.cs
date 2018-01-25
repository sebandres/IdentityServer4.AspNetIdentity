// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using IdentityModel;

namespace IdentityServer4.AspNetIdentity
{
    internal class UserClaimsFactory<TUser, TRole> : IUserClaimsPrincipalFactory<TUser>
        where TUser : class
        where TRole : class
    {
        private readonly Decorator<IUserClaimsPrincipalFactory<TUser>> _inner;
        private UserManager<TUser> _userManager;
        private RoleManager<TRole> _roleManager;

        public UserClaimsFactory(Decorator<IUserClaimsPrincipalFactory<TUser>> inner, UserManager<TUser> userManager, RoleManager<TRole> roleManager)
        {
            _inner = inner;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            var principal = await _inner.Instance.CreateAsync(user);
            var identity = principal.Identities.First();

            if (!identity.HasClaim(x => x.Type == JwtClaimTypes.Subject))
            {
                var sub = await _userManager.GetUserIdAsync(user);
                identity.AddClaim(new Claim(JwtClaimTypes.Subject, sub));
            }

            var username = await _userManager.GetUserNameAsync(user);
            var usernameClaim = identity.FindFirst(claim => claim.Type == _userManager.Options.ClaimsIdentity.UserNameClaimType && claim.Value == username);
            if (usernameClaim != null)
            {
                identity.RemoveClaim(usernameClaim);
                identity.AddClaim(new Claim(JwtClaimTypes.PreferredUserName, username));
            }

            if (!identity.HasClaim(x => x.Type == JwtClaimTypes.Name))
            {
                identity.AddClaim(new Claim(JwtClaimTypes.Name, username));
            }

            if (_userManager.SupportsUserEmail)
            {
                var email = await _userManager.GetEmailAsync(user);
                if (!String.IsNullOrWhiteSpace(email))
                {
                    identity.AddClaims(new[]
                    {
                        new Claim(JwtClaimTypes.Email, email),
                        new Claim(JwtClaimTypes.EmailVerified,
                            await _userManager.IsEmailConfirmedAsync(user) ? "true" : "false", ClaimValueTypes.Boolean)
                    });
                }
            }

            if (_userManager.SupportsUserPhoneNumber)
            {
                var phoneNumber = await _userManager.GetPhoneNumberAsync(user);
                if (!String.IsNullOrWhiteSpace(phoneNumber))
                {
                    identity.AddClaims(new[]
                    {
                        new Claim(JwtClaimTypes.PhoneNumber, phoneNumber),
                        new Claim(JwtClaimTypes.PhoneNumberVerified,
                            await _userManager.IsPhoneNumberConfirmedAsync(user) ? "true" : "false", ClaimValueTypes.Boolean)
                    });
                }
            }

            if (_userManager.SupportsUserRole)
            {
                var roles = await _userManager.GetRolesAsync(user);

                // Multiple roles supported
                identity.AddClaims(roles.Select(role => new Claim(JwtClaimTypes.Role, role)));

                foreach (var role in roles)
                {
                    identity.AddClaims(await _roleManager.GetClaimsAsync(await _roleManager.FindByNameAsync(role)));
                }
            }

            return principal;
        }
    }
}
