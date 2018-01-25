// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using System.Security.Claims;
using Host.Data;
using Host.Models;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Host
{
    public class SeedData
    {
        public static void EnsureSeedData(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
                context.Database.Migrate();

                // Setup roles
                var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                var managerRole = roleMgr.FindByIdAsync("Manager").Result;
                if (managerRole == null)
                {
                    managerRole = new IdentityRole("Manager");
                    var result = roleMgr.CreateAsync(managerRole).Result;
                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }

                    var sysAdminClaimResult = roleMgr.AddClaimAsync(managerRole, new Claim("sysadmin", "true")).Result;
                    if (!sysAdminClaimResult.Succeeded)
                    {
                        throw new Exception(sysAdminClaimResult.Errors.First().Description);
                    }

                    var writeAccessClaimResult = roleMgr.AddClaimAsync(managerRole, new Claim("write_access", "true")).Result;
                    if (!writeAccessClaimResult.Succeeded)
                    {
                        throw new Exception(writeAccessClaimResult.Errors.First().Description);
                    }
                    Console.WriteLine("Manager role created");
                }

                var employeeRole = roleMgr.FindByIdAsync("Employee").Result;
                if (employeeRole == null)
                {
                    employeeRole = new IdentityRole("Employee");
                    var result = roleMgr.CreateAsync(employeeRole).Result;
                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }

                    var claimResult = roleMgr.AddClaimAsync(employeeRole, new Claim("read_only", "true")).Result;
                    if (!claimResult.Succeeded)
                    {
                        throw new Exception(claimResult.Errors.First().Description);
                    }

                    Console.WriteLine("Employee role created");
                }

                var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var alice = userMgr.FindByNameAsync("alice").Result;
                if (alice == null)
                {
                    alice = new ApplicationUser
                    {
                        UserName = "alice"
                    };
                    var result = userMgr.CreateAsync(alice, "Pass123$").Result;
                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }

                    result = userMgr.AddClaimsAsync(alice, new Claim[]{
                        new Claim(JwtClaimTypes.Name, "Alice Smith"),
                        new Claim(JwtClaimTypes.GivenName, "Alice"),
                        new Claim(JwtClaimTypes.FamilyName, "Smith"),
                        new Claim(JwtClaimTypes.Email, "AliceSmith@email.com"),
                        new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        new Claim(JwtClaimTypes.WebSite, "http://alice.com"),
                        new Claim(JwtClaimTypes.Address, @"{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }", IdentityServer4.IdentityServerConstants.ClaimValueTypes.Json)
                    }).Result;
                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }

                    var addManagerResult = userMgr.AddToRoleAsync(alice, "Manager").Result;
                    if (!addManagerResult.Succeeded)
                    {
                        throw new Exception(addManagerResult.Errors.First().Description);
                    }

                    Console.WriteLine("alice created");
                }
                else
                {
                    Console.WriteLine("alice already exists");
                }

                var bob = userMgr.FindByNameAsync("bob").Result;
                if (bob == null)
                {
                    bob = new ApplicationUser
                    {
                        UserName = "bob"
                    };
                    var result = userMgr.CreateAsync(bob, "Pass123$").Result;
                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }

                    result = userMgr.AddClaimsAsync(bob, new Claim[]{
                        new Claim(JwtClaimTypes.Name, "Bob Smith"),
                        new Claim(JwtClaimTypes.GivenName, "Bob"),
                        new Claim(JwtClaimTypes.FamilyName, "Smith"),
                        new Claim(JwtClaimTypes.Email, "BobSmith@email.com"),
                        new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        new Claim(JwtClaimTypes.WebSite, "http://bob.com"),
                        new Claim(JwtClaimTypes.Address, @"{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }", IdentityServer4.IdentityServerConstants.ClaimValueTypes.Json),
                        new Claim("location", "somewhere")
                    }).Result;
                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }

                    var addEmployeeResult = userMgr.AddToRoleAsync(bob, "Employee").Result;
                    if (!addEmployeeResult.Succeeded)
                    {
                        throw new Exception(addEmployeeResult.Errors.First().Description);
                    }

                    Console.WriteLine("bob created");
                }
                else
                {
                    Console.WriteLine("bob already exists");
                }
            }
        }
    }
}
