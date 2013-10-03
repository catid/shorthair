/*
	Copyright (c) 2009-2011 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include <cat/io/Settings.hpp>
#include <cat/io/Log.hpp>
using namespace cat;

static Log *m_logging = 0;


//// Settings

CAT_REF_SINGLETON(Settings);

bool Settings::OnInitialize()
{
	AutoWriteLock lock(_lock);

	_file = new ragdoll::File;
	if (!_file) return false;

	_file->Read(CAT_SETTINGS_FILE);
	_file->Override(CAT_SETTINGS_OVERRIDE_FILE);

	lock.Release();

	// Initialize logging threshold
	EventSeverity threshold = (EventSeverity)getInt("IO.Log.Threshold", DEFAULT_LOG_LEVEL);
	Use(m_logging)->SetThreshold(threshold);

	return true;
}

void Settings::OnFinalize()
{
	if (getInt("IO.Settings.UnlinkOverride") == 1)
	{
		std::remove(CAT_SETTINGS_OVERRIDE_FILE);
	}

	AutoWriteLock lock(_lock);

	_file->Write(CAT_SETTINGS_FILE);

	delete _file;
	_file = 0;
}

int Settings::getInt(const char *name, int default_value)
{
	return _file->GetInt(name, default_value, &_lock);
}

std::string Settings::getStr(const char *name, const char *default_value)
{
	std::string value;
	_file->Get(name, default_value, value, &_lock);
	return value;
}

void Settings::setInt(const char *name, int value)
{
	_file->SetInt(name, value, &_lock);
}

void Settings::setStr(const char *name, const char *value)
{
	_file->Set(name, value, &_lock);
}
