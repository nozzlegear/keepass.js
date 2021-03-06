var babelify = require('babelify');
var browserify = require('browserify');
var gulp = require('gulp');
var bump = require('gulp-bump');
var run = require('gulp-run');
var uglify = require('gulp-uglify');
var rename = require('gulp-rename');
var concat = require('gulp-concat');
var del = require('del');
var yargs = require('yargs');
var runSequence = require('run-sequence');
var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');

var bowerRepository = '../keepass.js-bower';
var buildOutputDir = 'dist';

gulp.task('compile', function () {
    var b = browserify({
        entries: './src/keepass.js',
        transform: [babelify],
        standalone: 'Keepass'
    });

    return b.bundle()
        .pipe(source('keepass.js'))
        .pipe(buffer())
        .pipe(gulp.dest(buildOutputDir + '/'));
});

gulp.task('minify', function () {
    return gulp.src(buildOutputDir + '/keepass.js')
        .pipe(uglify())
        .pipe(rename({ extname: '.min.js' }))
        .pipe(gulp.dest(buildOutputDir));
});

gulp.task('minify-libs', function () {
    return gulp.src('libs/**/*.js')
        .pipe(concat('keepass-libs.min.js'))
        .pipe(uglify())
        .pipe(gulp.dest(buildOutputDir));
});

gulp.task('concat-with-libs', function () {
    return gulp.src([buildOutputDir + '/keepass-libs.min.js', buildOutputDir + '/keepass.min.js'])
        .pipe(concat('keepass-all.min.js'))
        .pipe(gulp.dest(buildOutputDir)); 
});

gulp.task('watch', ['compile'], function () {
    return gulp.watch('src/**/*.js', ['compile']);
});

gulp.task('clean', function () {
    return del([buildOutputDir]);
});

gulp.task('clean-bower-repo', function () {
    return del([buildOutputDir], { cwd: bowerRepository });
});

gulp.task('bump-version', function () {
    var argv = yargs.argv;
    return gulp.src(['package.json', 'bower.json'])
        .pipe(bump({ type: argv.type, version: argv.version }))
        .pipe(gulp.dest('.'));
});

gulp.task('copy-to-bower-repository', function () {
    return gulp.src(['bower.json', buildOutputDir + '/**/*'], { base: '.' })
        .pipe(gulp.dest(bowerRepository + '/'));
});

gulp.task('git-commit-bower-repo', function () {
    return gitCommit({ cwd: bowerRepository });
});

gulp.task('git-commit', function () {
    return gitCommit();
});

function gitCommit (runOpts) {
    var version = require('./package.json').version;
    
    var commands = [
        'git add -A',
        'git commit -m "Release v' + version + '"',
        'git tag v' + version
    ];
    
    if (yargs.argv.push) {
        commands.push('git push');
        commands.push('git push --tags');
    }
    
    // use gulp-run instead of gulp-git because gulp-git crashes the node process on my machine
    return run(commands.join(' && '), runOpts).exec();
}

gulp.task('dist-build', function (cb) {
    runSequence('clean', 'compile', 'minify', 'minify-libs', 'concat-with-libs', cb);
});

gulp.task('bower-build', function (cb) {
    runSequence('clean-bower-repo', 'copy-to-bower-repository', cb);
});

/** 
 * gulp release --type=major|minor|patch|prerelease
 *              --version=1.3.4
 *              --push
 */
gulp.task('release', function (cb) {
    runSequence('bump-version', 'dist-build', 'bower-build', 'git-commit-bower-repo', 'git-commit', cb);
});

gulp.task('default', ['compile']);
