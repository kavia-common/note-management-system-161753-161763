using NSwag;
using NSwag.Generation.Processors.Security;
using System.Text;
using System.Security.Cryptography;

// App bootstrap
var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers()
    .AddJsonOptions(o =>
    {
        // Ensure consistent casing
        o.JsonSerializerOptions.PropertyNamingPolicy = null;
    });

// EF Core setup (SQLite by default)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
                       ?? builder.Configuration["DB_CONNECTION_STRING"]
                       ?? "Data Source=notes.db";

builder.Services.AddDbContext<AppDbContext>(options =>
{
    Microsoft.EntityFrameworkCore.SqliteDbContextOptionsBuilderExtensions.UseSqlite(options, connectionString);
});

// Auth settings
var jwtKey = builder.Configuration["JWT__KEY"];
var jwtIssuer = builder.Configuration["JWT__ISSUER"] ?? "notes-app";
var jwtAudience = builder.Configuration["JWT__AUDIENCE"] ?? "notes-web";

// If no JWT key is provided via env/appsettings, generate a temporary dev key to avoid crashing in dev
if (string.IsNullOrWhiteSpace(jwtKey))
{
    jwtKey = Convert.ToBase64String(Encoding.UTF8.GetBytes("dev-insecure-key-change-in-prod-1234567890"));
}

var signingKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // allow http in dev
    options.SaveToken = true;
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,
        ValidateAudience = true,
        ValidAudience = jwtAudience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(2)
    };
});

builder.Services.AddAuthorization();

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.SetIsOriginAllowed(_ => true)
              .AllowCredentials()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// OpenAPI/Swagger (NSwag)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApiDocument(settings =>
{
    settings.Title = "Notes Backend API";
    settings.Version = "v1";
    settings.Description = "REST API for managing user notes with JWT authentication.";
    settings.DocumentProcessors.Add(new NSwag.Generation.Processors.Security.SecurityDefinitionAppender("JWT",
        new NSwag.OpenApiSecurityScheme
        {
            Type = NSwag.OpenApiSecuritySchemeType.ApiKey,
            Name = "Authorization",
            In = NSwag.OpenApiSecurityApiKeyLocation.Header,
            Description = "Type into the text box: Bearer {your JWT token}."
        }));
    settings.OperationProcessors.Add(new NSwag.Generation.Processors.Security.AspNetCoreOperationSecurityScopeProcessor("JWT"));
});

// App services and repositories
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<ITokenService>(sp =>
    new TokenService(jwtIssuer, jwtAudience, signingKey));
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<INoteRepository, NoteRepository>();
builder.Services.AddScoped<INoteService, NoteService>();

var app = builder.Build();

// Apply migrations / create database
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
    // Seed minimal dev user if none exists (useful for immediate testing)
    if (!db.Users.Any())
    {
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "demo@notes.app",
            DisplayName = "Demo User",
            PasswordHash = hasher.HashPassword("demo1234"),
            CreatedAtUtc = DateTime.UtcNow
        };
        db.Users.Add(user);
        db.SaveChanges();
    }
}

// Middlewares
app.UseCors("AllowAll");
app.UseOpenApi();
app.UseSwaggerUi(config =>
{
    config.Path = "/docs";
});
app.UseAuthentication();
app.UseAuthorization();

// Health check endpoint
// PUBLIC_INTERFACE
app.MapGet("/", () => new { message = "Healthy" })
   .WithName("Health")
   .WithTags("Health")
   .WithSummary("Health check")
   .WithDescription("Returns a static healthy message.");

// Auth endpoints
// PUBLIC_INTERFACE
app.MapPost("/auth/register", async (RegisterRequest request, IUserRepository users, IPasswordHasher hasher, ITokenService tokenService, AppDbContext db) =>
{
    /*
    Registers a user account and returns a JWT token.
    - Body: RegisterRequest { Email, Password, DisplayName }
    - Returns: AuthResponse { Token, ExpiresAtUtc, User }
    */
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new ErrorResponse("Email and Password are required."));
    }

    var existing = await users.GetByEmailAsync(request.Email);
    if (existing != null)
    {
        return Results.Conflict(new ErrorResponse("A user with this email already exists."));
    }

    var user = new User
    {
        Id = Guid.NewGuid(),
        Email = request.Email.Trim(),
        DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? request.Email : request.DisplayName.Trim(),
        PasswordHash = hasher.HashPassword(request.Password),
        CreatedAtUtc = DateTime.UtcNow
    };

    await users.AddAsync(user);
    await db.SaveChangesAsync();

    var token = tokenService.CreateToken(user);
    return Results.Ok(new AuthResponse
    {
        Token = token.Token,
        ExpiresAtUtc = token.ExpiresAtUtc,
        User = UserDto.FromEntity(user)
    });
})
.WithTags("Auth")
.WithSummary("Register a new user")
.WithDescription("Creates a new user and returns a JWT token.");

// PUBLIC_INTERFACE
app.MapPost("/auth/login", async (LoginRequest request, IUserRepository users, IPasswordHasher hasher, ITokenService tokenService) =>
{
    /*
    Authenticates a user and returns a JWT token.
    - Body: LoginRequest { Email, Password }
    - Returns: AuthResponse { Token, ExpiresAtUtc, User }
    */
    var user = await users.GetByEmailAsync(request.Email ?? string.Empty);
    if (user == null || !hasher.VerifyHashedPassword(user.PasswordHash, request.Password ?? string.Empty))
    {
        return Results.Unauthorized();
    }

    var token = tokenService.CreateToken(user);
    return Results.Ok(new AuthResponse
    {
        Token = token.Token,
        ExpiresAtUtc = token.ExpiresAtUtc,
        User = UserDto.FromEntity(user)
    });
})
.WithTags("Auth")
.WithSummary("Login")
.WithDescription("Authenticates a user and returns a JWT token.");

// Notes endpoints (CRUD) - require auth
var notesGroup = app.MapGroup("/notes").RequireAuthorization().WithTags("Notes");

// PUBLIC_INTERFACE
notesGroup.MapGet("/", async (HttpContext httpContext, INoteRepository repo) =>
{
    /*
    Returns all notes for the authenticated user.
    - Header: Authorization: Bearer <token>
    - Returns: List<NoteDto>
    */
    var userId = httpContext.User.GetUserId();
    if (userId == null) return Results.Unauthorized();

    var items = await repo.GetAllByUserAsync(userId.Value);
    return Results.Ok(items.Select(NoteDto.FromEntity));
})
.WithName("GetNotes")
.WithSummary("List notes")
.WithDescription("List all notes for the authenticated user.");

// PUBLIC_INTERFACE
notesGroup.MapGet("/{id:guid}", async (HttpContext httpContext, Guid id, INoteRepository repo) =>
{
    /*
    Returns a specific note by id for the authenticated user.
    - Route: /notes/{id}
    - Returns: NoteDto or 404
    */
    var userId = httpContext.User.GetUserId();
    if (userId == null) return Results.Unauthorized();

    var note = await repo.GetByIdAsync(id, userId.Value);
    if (note == null) return Results.NotFound(new ErrorResponse("Note not found."));
    return Results.Ok(NoteDto.FromEntity(note));
})
.WithName("GetNoteById")
.WithSummary("Get note")
.WithDescription("Get a single note by id for the authenticated user.");

// PUBLIC_INTERFACE
notesGroup.MapPost("/", async (HttpContext httpContext, CreateNoteRequest request, INoteService service) =>
{
    /*
    Creates a new note.
    - Body: CreateNoteRequest { Title, Content }
    - Returns: NoteDto
    */
    var userId = httpContext.User.GetUserId();
    if (userId == null) return Results.Unauthorized();

    var created = await service.CreateAsync(userId.Value, request);
    return Results.Created($"/notes/{created.Id}", NoteDto.FromEntity(created));
})
.WithName("CreateNote")
.WithSummary("Create note")
.WithDescription("Create a new note for the authenticated user.");

// PUBLIC_INTERFACE
notesGroup.MapPut("/{id:guid}", async (HttpContext httpContext, Guid id, UpdateNoteRequest request, INoteService service) =>
{
    /*
    Updates an existing note.
    - Route: /notes/{id}
    - Body: UpdateNoteRequest { Title, Content, IsArchived }
    - Returns: NoteDto
    */
    var userId = httpContext.User.GetUserId();
    if (userId == null) return Results.Unauthorized();

    var updated = await service.UpdateAsync(userId.Value, id, request);
    if (updated == null) return Results.NotFound(new ErrorResponse("Note not found."));
    return Results.Ok(NoteDto.FromEntity(updated));
})
.WithName("UpdateNote")
.WithSummary("Update note")
.WithDescription("Update an existing note for the authenticated user.");

// PUBLIC_INTERFACE
notesGroup.MapDelete("/{id:guid}", async (HttpContext httpContext, Guid id, INoteService service) =>
{
    /*
    Deletes a note.
    - Route: /notes/{id}
    - Returns: 204 No Content
    */
    var userId = httpContext.User.GetUserId();
    if (userId == null) return Results.Unauthorized();

    var deleted = await service.DeleteAsync(userId.Value, id);
    if (!deleted) return Results.NotFound(new ErrorResponse("Note not found."));
    return Results.NoContent();
})
.WithName("DeleteNote")
.WithSummary("Delete note")
.WithDescription("Delete a note for the authenticated user.");

// PUBLIC_INTERFACE
app.MapGet("/docs/websocket-info", () => new
{
    message = "No WebSocket endpoints are used in this project. All communication uses REST over HTTP."
})
.WithTags("Docs")
.WithSummary("WebSocket Info")
.WithDescription("Project note stating no WebSocket endpoints are used.");

// Run
app.Run();

#region Data Layer

public class AppDbContext : Microsoft.EntityFrameworkCore.DbContext
{
    public AppDbContext(Microsoft.EntityFrameworkCore.DbContextOptions<AppDbContext> options) : base(options) { }

    public Microsoft.EntityFrameworkCore.DbSet<User> Users => Set<User>();
    public Microsoft.EntityFrameworkCore.DbSet<Note> Notes => Set<Note>();

    protected override void OnModelCreating(Microsoft.EntityFrameworkCore.ModelBuilder modelBuilder)
    {
        // User
        modelBuilder.Entity<User>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Email).IsUnique();
            e.Property(x => x.Email).IsRequired().HasMaxLength(256);
            e.Property(x => x.DisplayName).HasMaxLength(256);
            e.Property(x => x.PasswordHash).IsRequired();
            e.Property(x => x.CreatedAtUtc).IsRequired();
        });

        // Note
        modelBuilder.Entity<Note>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.UserId, x.CreatedAtUtc });
            e.Property(x => x.Title).HasMaxLength(256);
            e.Property(x => x.Content).HasColumnType("TEXT");
            e.Property(x => x.CreatedAtUtc).IsRequired();
            e.Property(x => x.UpdatedAtUtc).IsRequired();
            e.Property(x => x.IsArchived).HasDefaultValue(false);
            e.HasOne<User>()
             .WithMany()
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        base.OnModelCreating(modelBuilder);
    }
}

public class User
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
}

public class Note
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public bool IsArchived { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}

#endregion

#region DTOs and Requests

public record ErrorResponse(string Message);

public class UserDto
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;

    public static UserDto FromEntity(User u) => new()
    {
        Id = u.Id,
        Email = u.Email,
        DisplayName = u.DisplayName
    };
}

public class NoteDto
{
    public Guid Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public bool IsArchived { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }

    public static NoteDto FromEntity(Note n) => new()
    {
        Id = n.Id,
        Title = n.Title,
        Content = n.Content,
        IsArchived = n.IsArchived,
        CreatedAtUtc = n.CreatedAtUtc,
        UpdatedAtUtc = n.UpdatedAtUtc
    };
}

public class RegisterRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
}

public class LoginRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class AuthResponse
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
    public UserDto User { get; set; } = new();
}

public class CreateNoteRequest
{
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
}

public class UpdateNoteRequest
{
    public string? Title { get; set; }
    public string? Content { get; set; }
    public bool? IsArchived { get; set; }
}

#endregion

#region Auth Helpers

public interface IPasswordHasher
{
    // PUBLIC_INTERFACE
    string HashPassword(string password);
    // PUBLIC_INTERFACE
    bool VerifyHashedPassword(string hashedPassword, string providedPassword);
}

public class PasswordHasher : IPasswordHasher
{
    // A simple PBKDF2 password hasher
    public string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("Password cannot be empty.");

        // generate a salt
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        var salt = new byte[16];
        rng.GetBytes(salt);

        // derive key
        using var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(password, salt, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256);
        var key = pbkdf2.GetBytes(32);

        var result = new byte[1 + salt.Length + key.Length];
        result[0] = 0x01; // version
        Buffer.BlockCopy(salt, 0, result, 1, salt.Length);
        Buffer.BlockCopy(key, 0, result, 1 + salt.Length, key.Length);
        return Convert.ToBase64String(result);
    }

    public bool VerifyHashedPassword(string hashedPassword, string providedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword) || string.IsNullOrWhiteSpace(providedPassword))
            return false;

        var bytes = Convert.FromBase64String(hashedPassword);
        if (bytes.Length < 1 + 16 + 32 || bytes[0] != 0x01) return false;

        var salt = new byte[16];
        Buffer.BlockCopy(bytes, 1, salt, 0, salt.Length);
        var storedKey = new byte[32];
        Buffer.BlockCopy(bytes, 1 + salt.Length, storedKey, 0, storedKey.Length);

        using var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(providedPassword, salt, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256);
        var computed = pbkdf2.GetBytes(32);

        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(storedKey, computed);
    }
}

public static class ClaimsPrincipalExtensions
{
    // PUBLIC_INTERFACE
    public static Guid? GetUserId(this System.Security.Claims.ClaimsPrincipal principal)
    {
        var claim = principal.Claims.FirstOrDefault(c => c.Type == "sub" || c.Type == "userId");
        if (claim == null) return null;
        if (Guid.TryParse(claim.Value, out var id)) return id;
        return null;
    }
}

public interface ITokenService
{
    // PUBLIC_INTERFACE
    TokenResult CreateToken(User user);
}

public class TokenResult
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
}

public class TokenService : ITokenService
{
    private readonly string _issuer;
    private readonly string _audience;
    private readonly SymmetricSecurityKey _key;

    public TokenService(string issuer, string audience, SymmetricSecurityKey key)
    {
        _issuer = issuer;
        _audience = audience;
        _key = key;
    }

    public TokenResult CreateToken(User user)
    {
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddHours(12);

        var claims = new[]
        {
            new System.Security.Claims.Claim("sub", user.Id.ToString()),
            new System.Security.Claims.Claim("email", user.Email),
            new System.Security.Claims.Claim("name", user.DisplayName ?? user.Email)
        };

        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: expires,
            signingCredentials: creds
        );

        return new TokenResult
        {
            Token = handler.WriteToken(token),
            ExpiresAtUtc = expires
        };
    }
}

#endregion

#region Repositories and Services

public interface IUserRepository
{
    // PUBLIC_INTERFACE
    Task<User?> GetByEmailAsync(string email);
    // PUBLIC_INTERFACE
    Task AddAsync(User user);
}

public class UserRepository : IUserRepository
{
    private readonly AppDbContext _db;

    public UserRepository(AppDbContext db)
    {
        _db = db;
    }

    public Task<User?> GetByEmailAsync(string email)
    {
        return Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstOrDefaultAsync(
            Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.AsNoTracking(_db.Users),
            u => u.Email == email);
    }

    public async Task AddAsync(User user)
    {
        await _db.Users.AddAsync(user);
    }
}

public interface INoteRepository
{
    // PUBLIC_INTERFACE
    Task<List<Note>> GetAllByUserAsync(Guid userId);
    // PUBLIC_INTERFACE
    Task<Note?> GetByIdAsync(Guid id, Guid userId);
    // PUBLIC_INTERFACE
    Task AddAsync(Note note);
    // PUBLIC_INTERFACE
    Task UpdateAsync(Note note);
    // PUBLIC_INTERFACE
    Task<bool> DeleteAsync(Guid id, Guid userId);
}

public class NoteRepository : INoteRepository
{
    private readonly AppDbContext _db;

    public NoteRepository(AppDbContext db)
    {
        _db = db;
    }

    public Task<List<Note>> GetAllByUserAsync(Guid userId)
    {
        return System.Linq.AsyncEnumerable.ToListAsync(
            Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.AsNoTracking(
                _db.Notes.Where(n => n.UserId == userId).OrderByDescending(n => n.UpdatedAtUtc)));
    }

    public Task<Note?> GetByIdAsync(Guid id, Guid userId)
    {
        return Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstOrDefaultAsync(
            _db.Notes.Where(n => n.Id == id && n.UserId == userId));
    }

    public async Task AddAsync(Note note)
    {
        await _db.Notes.AddAsync(note);
        await _db.SaveChangesAsync();
    }

    public async Task UpdateAsync(Note note)
    {
        _db.Notes.Update(note);
        await _db.SaveChangesAsync();
    }

    public async Task<bool> DeleteAsync(Guid id, Guid userId)
    {
        var entity = await _db.Notes.FirstOrDefaultAsync(n => n.Id == id && n.UserId == userId);
        if (entity == null) return false;
        _db.Notes.Remove(entity);
        await _db.SaveChangesAsync();
        return true;
    }
}

public interface INoteService
{
    // PUBLIC_INTERFACE
    Task<Note> CreateAsync(Guid userId, CreateNoteRequest request);
    // PUBLIC_INTERFACE
    Task<Note?> UpdateAsync(Guid userId, Guid noteId, UpdateNoteRequest request);
    // PUBLIC_INTERFACE
    Task<bool> DeleteAsync(Guid userId, Guid noteId);
}

public class NoteService : INoteService
{
    private readonly INoteRepository _repo;

    public NoteService(INoteRepository repo)
    {
        _repo = repo;
    }

    public async Task<Note> CreateAsync(Guid userId, CreateNoteRequest request)
    {
        var now = DateTime.UtcNow;
        var note = new Note
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Title = request.Title?.Trim() ?? string.Empty,
            Content = request.Content ?? string.Empty,
            IsArchived = false,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };
        await _repo.AddAsync(note);
        return note;
    }

    public async Task<Note?> UpdateAsync(Guid userId, Guid noteId, UpdateNoteRequest request)
    {
        var entity = await _repo.GetByIdAsync(noteId, userId);
        if (entity == null) return null;

        if (request.Title != null) entity.Title = request.Title.Trim();
        if (request.Content != null) entity.Content = request.Content;
        if (request.IsArchived.HasValue) entity.IsArchived = request.IsArchived.Value;
        entity.UpdatedAtUtc = DateTime.UtcNow;

        await _repo.UpdateAsync(entity);
        return entity;
        }
    public Task<bool> DeleteAsync(Guid userId, Guid noteId) => _repo.DeleteAsync(noteId, userId);
}

#endregion

#region Config Extensions

public static class OpenApiExtensions
{
    // PUBLIC_INTERFACE
    public static Microsoft.AspNetCore.Builder.WebApplication MapOpenApiWithJwt(this Microsoft.AspNetCore.Builder.WebApplication app)
    {
        // Already configured above; helper left for extensibility
        return app;
    }
}

#endregion
